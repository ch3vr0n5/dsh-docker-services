import assert from 'node:assert/strict'
import {createHmac} from 'node:crypto'
import {mkdtemp, mkdir, realpath, symlink, writeFile} from 'node:fs/promises'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {createProxy, parseProxyConfig, type ProxyConfig} from '../src/proxy.js'

async function listen(server: http.Server, socket: string): Promise<void> { await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(socket, () => resolve()) }) }
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
