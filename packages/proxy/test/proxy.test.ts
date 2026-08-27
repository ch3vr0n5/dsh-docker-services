import assert from 'node:assert/strict'
import {randomBytes} from 'node:crypto'
import {chmod, lstat, mkdtemp, mkdir, realpath, symlink, unlink, writeFile} from 'node:fs/promises'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {once} from 'node:events'
import {proxyProtocolVersion, requestCanonical, responseCanonical, selectedHeaders, sha256Hex, signMac, type RequestBinding, type ResponseBinding} from '@dsh-docker-services/shared'
import {parseProxyConfig, startProxy, type ProxyConfig, type RunningProxy} from '../src/proxy.js'

async function listen(server: http.Server, socket: string): Promise<void> { await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve) }) }
async function close(server: http.Server): Promise<void> { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) }
function request(socket: string, route: string, headers: Record<string,string> = {}, body?: string): Promise<{status: number; body: string}> { return new Promise((resolve, reject) => { const req = http.request({socketPath: socket, path: route, method: body === undefined ? 'GET' : 'POST', headers: {...headers, ...(body === undefined ? {} : {'content-length': Buffer.byteLength(body)})}}, res => { const chunks: Buffer[]=[]; res.on('data', c=>chunks.push(c)); res.on('end',()=>resolve({status:res.statusCode ?? 0,body:Buffer.concat(chunks).toString()})); res.on('aborted',()=>resolve({status:res.statusCode ?? 0,body:Buffer.concat(chunks).toString()})) }); req.on('error',reject); req.end(body) }) }
async function collect(req: http.IncomingMessage): Promise<Buffer> { const chunks: Buffer[]=[]; for await (const chunk of req) chunks.push(Buffer.from(chunk)); return Buffer.concat(chunks) }

type Wire = {status: number; headers: Record<string,string>; body: Buffer; binding: RequestBinding}
type Handler = (request: {method: string; target: string; body: Buffer; binding: RequestBinding}, wire: Wire) => void | Promise<void>
function authenticatedController(key: string, handler: Handler, proofKey = key): http.Server {
  return http.createServer(async (req, res) => {
    if (req.url === '/v1/proxy-handshake') {
      const challenge = req.headers['x-dsh-proxy-challenge']; if (typeof challenge !== 'string') throw new Error('missing handshake challenge')
      const proof = signMac(Buffer.from(proofKey), 'handshake', Buffer.from(challenge, 'ascii'))
      const body = JSON.stringify({protocolVersion: 1, challenge, proof}); res.writeHead(200, {'content-type':'application/json','content-length':Buffer.byteLength(body)});res.end(body); return
    }
    const body = await collect(req); const assertion = String(req.headers['x-dsh-proxy-assertion'] ?? ''); const [encoded] = assertion.split('.'); assert(encoded)
    const claims = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as {sub: string; role: string}
    const binding: RequestBinding = {protocolVersion: proxyProtocolVersion, requestId: String(req.headers['x-dsh-request-id']), nonce: String(req.headers['x-dsh-request-nonce']), actor: claims.sub, role: claims.role, method: req.method ?? '', target: req.url ?? '', headers: selectedHeaders({'content-type': typeof req.headers['content-type'] === 'string' ? req.headers['content-type'] : undefined, 'content-length': typeof req.headers['content-length'] === 'string' ? req.headers['content-length'] : undefined}, ['content-type','content-length']), bodyDigest: sha256Hex(body), bodyLength: body.length}
    assert.equal(req.headers['x-dsh-protocol-version'], String(proxyProtocolVersion)); assert.equal(signMac(Buffer.from(key), 'request', requestCanonical(binding)), req.headers['x-dsh-request-mac'])
    const payload = Buffer.from('privileged-controller-output')
    const headers: Record<string,string> = {'content-type':'application/json','content-length':String(payload.length),'cache-control':'no-store','x-content-type-options':'nosniff','x-request-id':randomBytes(12).toString('hex')}
    const requestDigest = sha256Hex(requestCanonical(binding)); const response: ResponseBinding = {protocolVersion: proxyProtocolVersion, requestId: binding.requestId, nonce: binding.nonce, requestDigest, status: 200, headers: selectedHeaders(headers, ['content-type','content-length','cache-control','x-content-type-options','x-request-id']), bodyDigest: sha256Hex(payload), bodyLength: payload.length, outcome:'ok'}
    const wire: Wire = {status: 200, headers: {...headers, 'x-dsh-protocol-version':String(proxyProtocolVersion), 'x-dsh-request-id':binding.requestId, 'x-dsh-request-nonce':binding.nonce, 'x-dsh-request-digest':requestDigest, 'x-dsh-response-outcome':'ok', 'x-dsh-response-mac':signMac(Buffer.from(key), 'response', responseCanonical(response))}, body: payload, binding}
    await handler({method:req.method ?? '',target:req.url ?? '',body,binding},wire)
    res.writeHead(wire.status, wire.headers); res.end(wire.body)
  })
}
function config(root: string, keyFile: string, controllerSocketPath: string, values: Partial<ProxyConfig> = {}): ProxyConfig { return {schemaVersion:1,socketPath:path.join(root,'proxy.sock'),controllerSocketPath,keyFile,issuer:'proxy',audience:'host',actor:'personal-harness',role:'viewer',controllerConnections:1,...values} }
async function fixture(t: test.TestContext, handler: Handler, values: Partial<ProxyConfig> = {}): Promise<{proxy: RunningProxy; socket: string}> {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-'))); const run=path.join(root,'run');await mkdir(run,{mode:0o700});const key='k'.repeat(32);const keyFile=path.join(root,'key');await writeFile(keyFile,key,{mode:0o600});const controllerSocket=path.join(run,'controller.sock');const controller=authenticatedController(key,handler);await listen(controller,controllerSocket);const proxy=await startProxy(config(run,keyFile,controllerSocket,values));t.after(async()=>{await proxy.close();await close(controller)});return {proxy,socket:proxy.socketPath}
}

test('proxy binds each exact request and verified complete response before forwarding', async t => {
  let seen: RequestBinding | undefined; const {socket}=await fixture(t,(request)=>{seen=request.binding});const value=await request(socket,'/v1/services?limit=2',{'x-dsh-role':'operator'});assert.equal(value.status,200);assert.equal(value.body,'privileged-controller-output');assert.equal(seen?.actor,'personal-harness');assert.equal(seen?.role,'viewer');assert.equal(seen?.target,'/v1/services?limit=2')
})

test('proxy rejects altered, replayed, cross-request, malformed, truncated, or oversized authenticated responses without partial output', async t => {
  const cases: Array<[string,(wire: Wire)=>void]> = [
    ['request id', wire => { wire.headers['x-dsh-request-id']='different-request-id-0001' }], ['nonce', wire => { wire.headers['x-dsh-request-nonce']='different-nonce-0000001' }], ['version', wire => { wire.headers['x-dsh-protocol-version']='2' }], ['outcome', wire => { wire.headers['x-dsh-response-outcome']='error' }], ['status', wire => { wire.status=201 }], ['selected header', wire => { wire.headers['content-type']='text/plain' }], ['body', wire => { wire.body=Buffer.from('substituted privileged output') }], ['length', wire => { wire.headers['content-length']='1' }], ['mac', wire => { wire.headers['x-dsh-response-mac']='malformed' }], ['extra framing', wire => { wire.headers['transfer-encoding']='chunked' }]
  ]
  for (const [name, mutate] of cases) {
    const {socket}=await fixture(t,(_request,wire)=>mutate(wire)); const result=await request(socket,'/v1/services');assert.equal(result.status,502,name);assert.equal(result.body.includes('privileged'),false,name)
  }
})

test('a valid response cannot be replayed across a different request or pinned lane', async t => {
  let prior: Wire | undefined
  const {socket}=await fixture(t,(_request,wire)=>{ if (prior) { wire.status=prior.status;wire.headers={...prior.headers};wire.body=Buffer.from(prior.body) } else prior={status:wire.status,headers:{...wire.headers},body:Buffer.from(wire.body),binding:wire.binding} },{controllerConnections:2})
  const first=await request(socket,'/v1/services?request=one');assert.equal(first.status,200)
  const second=await request(socket,'/v1/services?request=two');assert.equal(second.status,502);assert.equal(second.body.includes('privileged'),false)
})

test('configuration, body bounds, pinned lanes, and shutdown remain fail closed', async t => {
  assert.throws(()=>parseProxyConfig({schemaVersion:1,socketPath:'/run/a',controllerSocketPath:'/run/b',keyFile:'/run/k',issuer:'proxy',audience:'host',actor:'harness',role:'viewer',extra:true}),/unsupported/)
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-bounds-')));const run=path.join(root,'run');await mkdir(run,{mode:0o700});const target=path.join(root,'target');await writeFile(target,'k'.repeat(32),{mode:0o600});const keyFile=path.join(root,'key');await symlink(target,keyFile);const controllerSocket=path.join(run,'controller.sock');const controller=authenticatedController('k'.repeat(32),(_request,wire)=>{wire.body=Buffer.alloc(4096,'x');wire.headers['content-length']='4096'});await listen(controller,controllerSocket);t.after(()=>close(controller));const base=config(run,keyFile,controllerSocket,{maxRequestBytes:1024,maxResponseBytes:1024});await assert.rejects(()=>startProxy(base),/symlink/);const realKey=path.join(root,'real-key');await writeFile(realKey,'k'.repeat(32),{mode:0o600});const proxy=await startProxy({...base,keyFile:realKey});t.after(()=>proxy.close());const oversized=await request(base.socketPath,'/v1/services',{},'x'.repeat(2048));assert.equal(oversized.status,413);const response=await request(base.socketPath,'/v1/services');assert.equal(response.status,502);assert.equal(response.body.includes('privileged'),false)
})

test('startup rejects insecure ancestry and endpoint replacement cannot redirect pinned traffic', async t => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-auth-')));const key='k'.repeat(32);const keyFile=path.join(root,'key');await writeFile(keyFile,key,{mode:0o600});const insecure=path.join(root,'insecure');await mkdir(insecure,{mode:0o777});await chmod(insecure,0o777);const insecureSocket=path.join(insecure,'controller.sock');const first=authenticatedController(key,()=>undefined);await listen(first,insecureSocket);await assert.rejects(()=>startProxy(config(root,keyFile,insecureSocket)),/parent is insecure/);await close(first)
  const run=path.join(root,'run');await mkdir(run,{mode:0o700});const controllerSocket=path.join(run,'controller.sock');let original=0;const source=authenticatedController(key,()=>{original+=1});await listen(source,controllerSocket);const proxy=await startProxy(config(run,keyFile,controllerSocket));await unlink(controllerSocket);let replacement=0;const attacker=http.createServer((_req,res)=>{replacement+=1;res.end('attacker')});await listen(attacker,controllerSocket);t.after(async()=>{await proxy.close();await close(attacker)});const result=await request(proxy.socketPath,'/v1/services');assert.equal(result.status,200);assert.equal(original,1);assert.equal(replacement,0);await close(source);const unavailable=await request(proxy.socketPath,'/v1/services');assert.equal(unavailable.status,502);assert.equal(replacement,0)
})

test('public startup binds 0600 under umask 000 and incomplete inbound body cannot block shutdown', async () => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-mode-')));const run=path.join(root,'run');await mkdir(run,{mode:0o700});const key='k'.repeat(32);const keyFile=path.join(root,'key');await writeFile(keyFile,key,{mode:0o600});const controllerSocket=path.join(run,'controller.sock');const controller=authenticatedController(key,()=>undefined);await listen(controller,controllerSocket);const previous=process.umask(0);let proxy:RunningProxy|undefined
  try { proxy=await startProxy(config(run,keyFile,controllerSocket,{requestTimeoutMs:150}));assert.equal((await lstat(proxy.socketPath)).mode&0o777,0o600);const client=net.createConnection(proxy.socketPath);client.on('error',()=>undefined);await once(client,'connect');client.write('POST /v1/services HTTP/1.1\r\nHost: local\r\nContent-Length: 100\r\n\r\nx');const started=Date.now();await proxy.close();assert.ok(Date.now()-started<1200);client.destroy() } finally { process.umask(previous);if(proxy)await proxy.close();await close(controller) }
})
