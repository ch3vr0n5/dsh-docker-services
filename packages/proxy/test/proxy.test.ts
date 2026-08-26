import assert from 'node:assert/strict'
import {createHmac} from 'node:crypto'
import {chmod, mkdtemp, mkdir, realpath, symlink, unlink, writeFile} from 'node:fs/promises'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {once} from 'node:events'
import {createProxy, parseProxyConfig, type ProxyConfig} from '../src/proxy.js'

async function listen(server: http.Server, socket: string): Promise<void> { await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(socket, () => resolve()) }) }
async function close(server: http.Server): Promise<void> { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) }
function request(socket: string, route: string, headers: Record<string,string> = {}, body?: string): Promise<{status: number; body: string}> { return new Promise((resolve, reject) => { const req = http.request({socketPath: socket, path: route, method: body ? 'POST' : 'GET', headers: {...headers, ...(body ? {'content-length': Buffer.byteLength(body)} : {})}}, res => { const chunks: Buffer[]=[]; res.on('data', c=>chunks.push(c)); res.on('end',()=>resolve({status:res.statusCode ?? 0,body:Buffer.concat(chunks).toString()})) }); req.on('error',reject); req.end(body) }) }

test('proxy strips caller identity and signs one configured role', async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'dsh-proxy-'))); const run = path.join(root, 'run'); await mkdir(run, {mode:0o700})
  const keyFile = path.join(root, 'key'); await writeFile(keyFile, 'k'.repeat(32), {mode:0o600})
  const controllerSocket = path.join(run, 'controller.sock'); const proxySocket = path.join(run, 'proxy.sock')
  const seen = new Set<string>()
  const controller = http.createServer((req,res) => {
    const raw=req.headers['x-dsh-proxy-assertion']; if(typeof raw!=='string') { res.writeHead(401); res.end(); return }
    const [encoded,signature,extra]=raw.split('.'); const expected=createHmac('sha256','k'.repeat(32)).update(encoded ?? '').digest('base64url')
    if(!encoded||signature!==expected||extra||seen.has(raw)){res.writeHead(401);res.end();return} seen.add(raw)
    const claims=JSON.parse(Buffer.from(encoded,'base64url').toString()); const body=JSON.stringify(claims); res.writeHead(200,{'content-type':'application/json','content-length':Buffer.byteLength(body)}); res.end(body)
  }); await listen(controller,controllerSocket); t.after(()=>controller.close())
  const config: ProxyConfig={schemaVersion:1,socketPath:proxySocket,controllerSocketPath:controllerSocket,keyFile,issuer:'proxy',audience:'host',actor:'personal-harness',role:'viewer'}
  const proxy=await createProxy(config); await listen(proxy,proxySocket); t.after(()=>proxy.close())
  const first=await request(proxySocket,'/v1/services',{'x-dsh-proxy-assertion':'forged','x-dsh-role':'operator'}); assert.equal(first.status,200); const claims=JSON.parse(first.body); assert.equal(claims.sub,'personal-harness'); assert.equal(claims.role,'viewer'); assert.equal(claims.iss,'proxy'); assert.equal(claims.aud,'host')
  const second=await request(proxySocket,'/v1/services'); assert.equal(second.status,200)
})

test('configuration and request bounds fail closed', async () => {
  assert.throws(()=>parseProxyConfig({schemaVersion:1,socketPath:'/run/a',controllerSocketPath:'/run/b',keyFile:'/run/k',issuer:'proxy',audience:'host',actor:'harness',role:'viewer',extra:true}),/unsupported/)
  assert.throws(()=>parseProxyConfig({schemaVersion:1,socketPath:'/run/../a',controllerSocketPath:'/run/b',keyFile:'/run/k',issuer:'proxy',audience:'host',actor:'harness',role:'viewer'}),/paths/)
})

test('proxy rejects a symlinked key and bounds both directions without partial output', async t => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-bounds-'))); const run=path.join(root,'run'); await mkdir(run,{mode:0o700}); const target=path.join(root,'target'); await writeFile(target,'k'.repeat(32),{mode:0o600}); const keyFile=path.join(root,'key'); await symlink(target,keyFile)
  const controllerSocket=path.join(run,'controller.sock'); let calls=0; const controller=http.createServer((_req,res)=>{calls+=1;const body='x'.repeat(4096);res.writeHead(200,{'content-length':body.length});res.end(body)}); await listen(controller,controllerSocket); t.after(()=>controller.close())
  const base: ProxyConfig={schemaVersion:1,socketPath:path.join(run,'proxy.sock'),controllerSocketPath:controllerSocket,keyFile,issuer:'proxy',audience:'host',actor:'harness',role:'viewer',maxRequestBytes:1024,maxResponseBytes:1024}
  await assert.rejects(()=>createProxy(base),/symlink/)
  await writeFile(path.join(root,'real-key'),'k'.repeat(32),{mode:0o600}); const proxy=await createProxy({...base,keyFile:path.join(root,'real-key')}); await listen(proxy,base.socketPath); t.after(()=>proxy.close())
  const oversized=await request(base.socketPath,'/v1/services',{},'x'.repeat(2048)); assert.equal(oversized.status,413); assert.equal(calls,0)
  const response=await request(base.socketPath,'/v1/services'); assert.equal(response.status,502); assert.equal(response.body.includes('x'.repeat(32)),false)
})

test('proxy rejects an insecure controller parent and a controller replacement after startup', async t => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-controller-'))); const keyFile=path.join(root,'key'); await writeFile(keyFile,'k'.repeat(32),{mode:0o600})
  const insecure=path.join(root,'i'); await mkdir(insecure,{mode:0o777}); await chmod(insecure,0o777)
  const insecureSocket=path.join(insecure,'s'); const insecureController=http.createServer(); await listen(insecureController,insecureSocket); t.after(()=>close(insecureController))
  const base: ProxyConfig={schemaVersion:1,socketPath:path.join(root,'proxy.sock'),controllerSocketPath:insecureSocket,keyFile,issuer:'proxy',audience:'host',actor:'harness',role:'viewer'}
  await assert.rejects(()=>createProxy(base),/parent is insecure/)

  const run=path.join(root,'r'); await mkdir(run,{mode:0o700}); const controllerSocket=path.join(run,'c'); let originalCalls=0; const original=http.createServer((_req,res)=>{originalCalls+=1;res.end('original')}); await listen(original,controllerSocket)
  const proxy=await createProxy({...base,socketPath:path.join(run,'p'),controllerSocketPath:controllerSocket}); await listen(proxy,path.join(run,'p')); t.after(()=>close(proxy))
  await close(original); await unlink(controllerSocket).catch(error=>{if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error})
  let replacementCalls=0; const replacement=http.createServer((_req,res)=>{replacementCalls+=1;res.end('replacement')}); await listen(replacement,controllerSocket); t.after(()=>close(replacement))
  const response=await request(path.join(run,'p'),'/v1/services'); assert.equal(response.status,502); assert.equal(originalCalls,0); assert.equal(replacementCalls,0)
})

test('request timeout bounds slow incomplete bodies and permits prompt shutdown', async t => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'dsh-proxy-timeout-'))); const run=path.join(root,'run'); await mkdir(run,{mode:0o700}); const keyFile=path.join(root,'key'); await writeFile(keyFile,'k'.repeat(32),{mode:0o600})
  const controllerSocket=path.join(run,'controller.sock'); let calls=0; const controller=http.createServer((_req,res)=>{calls+=1;res.end('unexpected')}); await listen(controller,controllerSocket); t.after(()=>close(controller))
  const proxySocket=path.join(run,'proxy.sock'); const proxy=await createProxy({schemaVersion:1,socketPath:proxySocket,controllerSocketPath:controllerSocket,keyFile,issuer:'proxy',audience:'host',actor:'harness',role:'viewer',requestTimeoutMs:150}); await listen(proxy,proxySocket)
  const client=net.createConnection(proxySocket); client.on('error',()=>undefined); await once(client,'connect')
  const closed=once(client,'close'); client.write('POST /v1/services HTTP/1.1\r\nHost: local\r\nContent-Length: 100\r\n\r\nx')
  await Promise.race([closed,new Promise<never>((_,reject)=>setTimeout(()=>reject(new Error('slow client was not closed')),1000))])
  assert.equal(calls,0)
  await close(proxy)
})
