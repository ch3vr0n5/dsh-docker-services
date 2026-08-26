import assert from 'node:assert/strict'
import {createHmac} from 'node:crypto'
import {chmod, lstat, mkdtemp, mkdir, realpath, symlink, unlink, writeFile} from 'node:fs/promises'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {once} from 'node:events'
import {parseProxyConfig, startProxy, type ProxyConfig, type RunningProxy} from '../src/proxy.js'

async function listen(server: http.Server, socket: string): Promise<void> { await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve) }) }
async function close(server: http.Server): Promise<void> { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) }
function request(socket: string, route: string, headers: Record<string,string> = {}, body?: string): Promise<{status: number; body: string}> { return new Promise((resolve, reject) => { const req = http.request({socketPath: socket, path: route, method: body ? 'POST' : 'GET', headers: {...headers, ...(body ? {'content-length': Buffer.byteLength(body)} : {})}}, res => { const chunks: Buffer[]=[]; res.on('data', c=>chunks.push(c)); res.on('end',()=>resolve({status:res.statusCode ?? 0,body:Buffer.concat(chunks).toString()})) }); req.on('error',reject); req.end(body) }) }

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void
function authenticatedController(key: string, handler: Handler, proofKey = key): http.Server {
  return http.createServer((req, res) => {
    if (req.url === '/v1/proxy-handshake') {
      const challenge = req.headers['x-dsh-proxy-challenge']; assert.equal(typeof challenge, 'string')
      const proof = createHmac('sha256', proofKey).update('dsh-docker-services/controller-proof/v1\n').update(challenge as string).digest('base64url')
      const body = JSON.stringify({protocolVersion: 1, challenge, proof}); res.writeHead(200, {'content-type':'application/json','content-length':Buffer.byteLength(body)}); res.end(body); return
    }
    handler(req, res)
  })
}

function config(root: string, keyFile: string, controllerSocketPath: string, values: Partial<ProxyConfig> = {}): ProxyConfig {
  return {schemaVersion:1,socketPath:path.join(root,'proxy.sock'),controllerSocketPath,keyFile,issuer:'proxy',audience:'host',actor:'personal-harness',role:'viewer',controllerConnections:1,...values}
}

test('proxy strips caller identity, signs one configured role, and uses unique assertions', async t => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-'))); const run=path.join(root,'run'); await mkdir(run,{mode:0o700}); const key='k'.repeat(32); const keyFile=path.join(root,'key'); await writeFile(keyFile,key,{mode:0o600})
  const controllerSocket=path.join(run,'controller.sock'); const proxySocket=path.join(run,'proxy.sock'); const seen=new Set<string>()
  const controller=authenticatedController(key,(req,res)=>{ const raw=req.headers['x-dsh-proxy-assertion']; if(typeof raw!=='string'){res.writeHead(401);res.end();return}; const [encoded,signature,extra]=raw.split('.'); const expected=createHmac('sha256',key).update(encoded??'').digest('base64url'); if(!encoded||signature!==expected||extra||seen.has(raw)){res.writeHead(401);res.end();return}; seen.add(raw); const claims=JSON.parse(Buffer.from(encoded,'base64url').toString()); const body=JSON.stringify(claims); res.writeHead(200,{'content-type':'application/json','content-length':Buffer.byteLength(body)});res.end(body) }); await listen(controller,controllerSocket)
  const proxy=await startProxy(config(run,keyFile,controllerSocket,{socketPath:proxySocket})); t.after(async()=>{await proxy.close();await close(controller)})
  const first=await request(proxySocket,'/v1/services',{'x-dsh-proxy-assertion':'forged','x-dsh-role':'operator'}); assert.equal(first.status,200); const claims=JSON.parse(first.body); assert.equal(claims.sub,'personal-harness');assert.equal(claims.role,'viewer');assert.equal(claims.iss,'proxy');assert.equal(claims.aud,'host')
  const second=await request(proxySocket,'/v1/services'); assert.equal(second.status,200); assert.equal(seen.size,2)
})

test('configuration and request bounds fail closed', () => {
  assert.throws(()=>parseProxyConfig({schemaVersion:1,socketPath:'/run/a',controllerSocketPath:'/run/b',keyFile:'/run/k',issuer:'proxy',audience:'host',actor:'harness',role:'viewer',extra:true}),/unsupported/)
  assert.throws(()=>parseProxyConfig({schemaVersion:1,socketPath:'/run/../a',controllerSocketPath:'/run/b',keyFile:'/run/k',issuer:'proxy',audience:'host',actor:'harness',role:'viewer'}),/paths/)
  assert.throws(()=>parseProxyConfig({schemaVersion:1,socketPath:'/run/a',controllerSocketPath:'/run/b',keyFile:'/run/k',issuer:'proxy',audience:'host',actor:'harness',role:'viewer',controllerConnections:17}),/connection/)
})

test('proxy rejects a symlinked key and bounds both directions without partial output', async t => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-bounds-')));const run=path.join(root,'run');await mkdir(run,{mode:0o700});const target=path.join(root,'target');await writeFile(target,'k'.repeat(32),{mode:0o600});const keyFile=path.join(root,'key');await symlink(target,keyFile)
  const controllerSocket=path.join(run,'controller.sock');let calls=0;const controller=authenticatedController('k'.repeat(32),(_req,res)=>{calls+=1;const body='x'.repeat(4096);res.writeHead(200,{'content-length':body.length});res.end(body)});await listen(controller,controllerSocket);t.after(()=>close(controller))
  const base=config(run,keyFile,controllerSocket,{maxRequestBytes:1024,maxResponseBytes:1024});await assert.rejects(()=>startProxy(base),/symlink/)
  const realKey=path.join(root,'real-key');await writeFile(realKey,'k'.repeat(32),{mode:0o600});const proxy=await startProxy({...base,keyFile:realKey});t.after(()=>proxy.close())
  const oversized=await request(base.socketPath,'/v1/services',{},'x'.repeat(2048));assert.equal(oversized.status,413);assert.equal(calls,0)
  const response=await request(base.socketPath,'/v1/services');assert.equal(response.status,502);assert.equal(response.body.includes('x'.repeat(32)),false)
})

test('startup rejects insecure ancestry and an endpoint that cannot prove key possession', async t => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-auth-')));const keyFile=path.join(root,'key');await writeFile(keyFile,'k'.repeat(32),{mode:0o600})
  const insecure=path.join(root,'insecure');await mkdir(insecure,{mode:0o777});await chmod(insecure,0o777);const insecureSocket=path.join(insecure,'controller.sock');const first=authenticatedController('k'.repeat(32),(_req,res)=>res.end());await listen(first,insecureSocket)
  await assert.rejects(()=>startProxy(config(root,keyFile,insecureSocket)),/parent is insecure/);await close(first)
  const run=path.join(root,'run');await mkdir(run,{mode:0o700});const fakeSocket=path.join(run,'fake.sock');const fake=authenticatedController('k'.repeat(32),(_req,res)=>res.end(),'x'.repeat(32));await listen(fake,fakeSocket);t.after(()=>close(fake))
  await assert.rejects(()=>startProxy(config(run,keyFile,fakeSocket)),/authentication failed/);await assert.rejects(()=>lstat(path.join(run,'proxy.sock')),/ENOENT/)
})

test('Linux pathname replacement cannot redirect traffic from startup-pinned connections', async t => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-pin-')));const run=path.join(root,'run');await mkdir(run,{mode:0o700});const key='k'.repeat(32);const keyFile=path.join(root,'key');await writeFile(keyFile,key,{mode:0o600});const controllerSocket=path.join(run,'controller.sock')
  let originalCalls=0;const original=authenticatedController(key,(_req,res)=>{originalCalls+=1;res.end('original')});await listen(original,controllerSocket)
  const proxy=await startProxy(config(run,keyFile,controllerSocket));await unlink(controllerSocket)
  let replacementCalls=0;const replacement=http.createServer((_req,res)=>{replacementCalls+=1;res.end('replacement')});await listen(replacement,controllerSocket)
  t.after(async()=>{await proxy.close();await close(replacement)})
  const responses=await Promise.all(Array.from({length:12},()=>request(proxy.socketPath,'/v1/services')));assert.equal(responses.every(value=>value.status===200&&value.body==='original'),true);assert.equal(originalCalls,12);assert.equal(replacementCalls,0)
  await close(original);const unavailable=await request(proxy.socketPath,'/v1/services');assert.equal(unavailable.status,502);assert.equal(replacementCalls,0)
})

test('public startup binds mode 0600 under umask 000 and shutdown remains bounded', async () => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-mode-')));const run=path.join(root,'run');await mkdir(run,{mode:0o700});const key='k'.repeat(32);const keyFile=path.join(root,'key');await writeFile(keyFile,key,{mode:0o600});const controllerSocket=path.join(run,'controller.sock');let calls=0;const controller=authenticatedController(key,(_req,res)=>{calls+=1;res.end('unexpected')});await listen(controller,controllerSocket)
  const previous=process.umask(0);let proxy:RunningProxy|undefined
  try { proxy=await startProxy(config(run,keyFile,controllerSocket,{requestTimeoutMs:150}));assert.equal((await lstat(proxy.socketPath)).mode&0o777,0o600)
    const client=net.createConnection(proxy.socketPath);client.on('error',()=>undefined);await once(client,'connect');client.write('POST /v1/services HTTP/1.1\r\nHost: local\r\nContent-Length: 100\r\n\r\nx')
    const started=Date.now();await proxy.close();assert.ok(Date.now()-started<1200);assert.equal(calls,0);client.destroy()
  } finally { process.umask(previous);if(proxy)await proxy.close();await close(controller) }
})
