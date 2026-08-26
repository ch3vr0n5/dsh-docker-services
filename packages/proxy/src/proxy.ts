import {createHmac, randomBytes, timingSafeEqual} from 'node:crypto'
import {constants as fsConstants} from 'node:fs'
import {lstat, mkdir, open, rm} from 'node:fs/promises'
import http, {type ClientRequestArgs, type IncomingMessage, type ServerResponse} from 'node:http'
import net from 'node:net'
import path from 'node:path'
import type {Duplex} from 'node:stream'
import {patterns} from '@dsh-docker-services/shared'

export type ProxyConfig = {
  schemaVersion: 1
  socketPath: string
  controllerSocketPath: string
  keyFile: string
  issuer: string
  audience: string
  actor: string
  role: string
  assertionTtlSeconds?: number
  socketMode?: 0o600 | 0o660
  requestTimeoutMs?: number
  maxRequestBytes?: number
  maxResponseBytes?: number
  controllerConnections?: number
}

export type RunningProxy = {
  readonly server: http.Server
  readonly socketPath: string
  close(): Promise<void>
}

const absolute = (value: unknown): value is string => typeof value === 'string' && patterns.absolute.test(value) && path.resolve(value) === value
const bounded = (value: unknown, min: number, max: number): value is number => Number.isInteger(value) && Number(value) >= min && Number(value) <= max
const owned = (info: {uid: number}): boolean => typeof process.getuid !== 'function' || info.uid === 0 || info.uid === process.getuid()

function trustedDirectory(info: {isDirectory(): boolean; isSymbolicLink(): boolean; mode: number; uid: number}): boolean {
  if (!info.isDirectory() || info.isSymbolicLink() || !owned(info)) return false
  if ((info.mode & 0o022) === 0) return true
  return info.uid === 0 && (info.mode & 0o1000) !== 0
}

async function trustedParents(target: string): Promise<void> {
  const directory = path.dirname(target)
  let component = path.parse(directory).root
  for (const part of directory.slice(component.length).split(path.sep).filter(Boolean)) {
    const info = await lstat(component)
    if (!trustedDirectory(info)) throw new Error('proxy path parent is insecure')
    component = path.join(component, part)
  }
  const info = await lstat(component)
  if (!trustedDirectory(info)) throw new Error('proxy path parent is insecure')
}

async function trustedControllerSocket(file: string): Promise<void> {
  await trustedParents(file)
  const info = await lstat(file)
  if (!info.isSocket() || info.isSymbolicLink() || !owned(info) || (info.mode & 0o022) !== 0) throw new Error('controller socket is insecure')
}

export function parseProxyConfig(value: unknown): ProxyConfig {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid proxy configuration')
  const c = value as Partial<ProxyConfig>
  const expected = ['actor','assertionTtlSeconds','audience','controllerConnections','controllerSocketPath','issuer','keyFile','maxRequestBytes','maxResponseBytes','requestTimeoutMs','role','schemaVersion','socketMode','socketPath']
  if (Object.keys(c).some(key => !expected.includes(key))) throw new Error('proxy configuration contains unsupported fields')
  if (c.schemaVersion !== 1 || !absolute(c.socketPath) || !absolute(c.controllerSocketPath) || !absolute(c.keyFile)) throw new Error('proxy paths must be normalized absolute paths')
  if (c.socketPath === c.controllerSocketPath || !patterns.identifier.test(c.issuer ?? '') || !patterns.identifier.test(c.audience ?? '') || !patterns.identifier.test(c.actor ?? '') || !patterns.identifier.test(c.role ?? '')) throw new Error('invalid proxy identity configuration')
  if (c.socketMode !== undefined && ![0o600, 0o660].includes(c.socketMode)) throw new Error('proxy socket mode must be 0600 or 0660')
  if (c.assertionTtlSeconds !== undefined && !bounded(c.assertionTtlSeconds, 5, 300)) throw new Error('invalid assertion TTL')
  if (c.requestTimeoutMs !== undefined && !bounded(c.requestTimeoutMs, 100, 60_000)) throw new Error('invalid proxy timeout')
  if (c.maxRequestBytes !== undefined && !bounded(c.maxRequestBytes, 1024, 1024 * 1024)) throw new Error('invalid request bound')
  if (c.maxResponseBytes !== undefined && !bounded(c.maxResponseBytes, 1024, 8 * 1024 * 1024)) throw new Error('invalid response bound')
  if (c.controllerConnections !== undefined && !bounded(c.controllerConnections, 1, 16)) throw new Error('invalid controller connection count')
  return c as ProxyConfig
}

async function protectedKey(file: string): Promise<Buffer> {
  await trustedParents(file)
  if ((await lstat(file)).isSymbolicLink()) throw new Error('proxy key file is a symlink')
  const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
  try {
    const stat = await handle.stat()
    if (!stat.isFile() || stat.nlink !== 1 || !owned(stat) || (stat.mode & 0o022) !== 0 || stat.size < 32 || stat.size > 4096) throw new Error('proxy key file is insecure')
    return await handle.readFile()
  } finally { await handle.close() }
}

function assertion(key: Buffer, config: ProxyConfig): string {
  const now = Math.floor(Date.now() / 1000)
  const claims = {iss: config.issuer, aud: config.audience, sub: config.actor, role: config.role, iat: now, exp: now + (config.assertionTtlSeconds ?? 30), nonce: randomBytes(18).toString('base64url')}
  const encoded = Buffer.from(JSON.stringify(claims)).toString('base64url')
  return `${encoded}.${createHmac('sha256', key).update(encoded).digest('base64url')}`
}

function controllerProof(key: Buffer, challenge: string): Buffer { return createHmac('sha256', key).update('dsh-docker-services/controller-proof/v1\n').update(challenge).digest() }

function fail(res: ServerResponse, status: number): void {
  const body = JSON.stringify({error: {code: status === 413 ? 'bad_request' : 'unavailable', message: 'Docker services proxy rejected the request', requestId: randomBytes(12).toString('hex')}})
  if (!res.headersSent) res.writeHead(status, {'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff'})
  res.end(body)
}

async function collect(req: IncomingMessage, maximum: number): Promise<Buffer> {
  const chunks: Buffer[] = []; let bytes = 0
  for await (const chunk of req) { bytes += chunk.length; if (bytes > maximum) throw Object.assign(new Error('request too large'), {status: 413}); chunks.push(Buffer.from(chunk)) }
  return Buffer.concat(chunks)
}

class PinnedAgent extends http.Agent {
  private offered = false
  constructor(private readonly pinnedSocket: net.Socket) { super({keepAlive: true, maxSockets: 1, maxFreeSockets: 1, timeout: 0}) }
  override createConnection(_options: ClientRequestArgs, callback?: (error: Error | null, stream: Duplex) => void): Duplex | null | undefined {
    if (this.offered) { const error=new Error('pinned controller connection is unavailable'); if(callback)queueMicrotask(()=>callback(error,this.pinnedSocket));else throw error; return undefined }
    this.offered=true;if(callback)queueMicrotask(()=>callback(null,this.pinnedSocket));return this.pinnedSocket
  }
}

async function connectPinned(file: string, timeoutMs: number): Promise<{socket: net.Socket; agent: PinnedAgent}> {
  const socket = net.createConnection({path: file}); socket.setNoDelay(true)
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('controller connection timeout')) }, timeoutMs); timer.unref()
    socket.once('connect', () => { clearTimeout(timer); resolve() }); socket.once('error', error => { clearTimeout(timer); reject(error) })
  })
  return {socket, agent: new PinnedAgent(socket)}
}

async function authenticatePinnedController(agent: PinnedAgent, key: Buffer, config: ProxyConfig, timeoutMs: number): Promise<void> {
  const challenge = randomBytes(32).toString('base64url')
  const result = await new Promise<{status: number; body: Buffer}>((resolve, reject) => {
    const request = http.request({agent, host: 'controller.local', method: 'GET', path: '/v1/proxy-handshake', headers: {'x-dsh-proxy-assertion': assertion(key, config), 'x-dsh-proxy-challenge': challenge}}, response => {
      const chunks: Buffer[] = []; let bytes = 0
      response.on('data', chunk => { bytes += chunk.length; if (bytes > 4096) { request.destroy(new Error('controller handshake response too large')); return }; chunks.push(Buffer.from(chunk)) })
      response.on('end', () => resolve({status: response.statusCode ?? 0, body: Buffer.concat(chunks)})); response.on('error', reject)
    })
    const timer = setTimeout(() => request.destroy(new Error('controller handshake timeout')), timeoutMs); timer.unref()
    request.once('close', () => clearTimeout(timer)); request.once('error', reject); request.end()
  })
  if (result.status !== 200) throw new Error('controller authentication failed')
  let value: unknown; try { value = JSON.parse(result.body.toString('utf8')) } catch { throw new Error('controller authentication failed') }
  const response = value as {protocolVersion?: unknown; challenge?: unknown; proof?: unknown}
  if (response.protocolVersion !== 1 || response.challenge !== challenge || typeof response.proof !== 'string') throw new Error('controller authentication failed')
  let actual: Buffer; try { actual = Buffer.from(response.proof, 'base64url') } catch { throw new Error('controller authentication failed') }
  const expected = controllerProof(key, challenge)
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error('controller authentication failed')
}

async function prepareOutputPath(config: ProxyConfig): Promise<void> {
  await mkdir(path.dirname(config.socketPath), {recursive: true, mode: 0o700}); await trustedParents(config.socketPath)
  const existing = await lstat(config.socketPath).catch(() => undefined)
  if (existing && (!existing.isSocket() || !owned(existing))) throw new Error('proxy socket path exists and is not an owned socket')
  if (existing) await rm(config.socketPath)
}

async function bindPrivate(server: http.Server, config: ProxyConfig): Promise<void> {
  const mode = config.socketMode ?? 0o600
  const listening = new Promise<void>((resolve, reject) => { server.once('error', reject); server.once('listening', resolve) })
  const previous = process.umask(0o777 & ~mode)
  try { server.listen(config.socketPath) } finally { process.umask(previous) }
  await listening
  const info = await lstat(config.socketPath)
  if (!info.isSocket() || !owned(info) || (info.mode & 0o777) !== mode) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); throw new Error('proxy socket was not bound with the required mode') }
}

export async function startProxy(configInput: ProxyConfig): Promise<RunningProxy> {
  const config = parseProxyConfig(configInput); const requestTimeoutMs = config.requestTimeoutMs ?? 15_000; const key = await protectedKey(config.keyFile)
  await prepareOutputPath(config); await trustedControllerSocket(config.controllerSocketPath)
  const lanes: Array<{socket: net.Socket; agent: PinnedAgent}> = []
  try {
    for (let index = 0; index < (config.controllerConnections ?? 4); index += 1) { const lane = await connectPinned(config.controllerSocketPath, requestTimeoutMs); try { await authenticatePinnedController(lane.agent, key, config, requestTimeoutMs); lanes.push(lane) } catch (error) { lane.agent.destroy(); throw error } }
  } catch (error) { for (const lane of lanes) lane.agent.destroy(); throw error }
  let laneIndex = 0
  const server = http.createServer(async (clientRequest, clientResponse) => {
    let upstream: http.ClientRequest | undefined; let expired = false
    const expire = () => { if (expired) return; expired = true; const error = Object.assign(new Error('proxy timeout'), {status: 408}); upstream?.destroy(error); clientRequest.destroy(error) }
    const timer = setTimeout(expire, requestTimeoutMs); timer.unref()
    try {
      const body = await collect(clientRequest, config.maxRequestBytes ?? 64 * 1024); if (expired) return
      const lane = lanes[laneIndex++ % lanes.length]!
      await new Promise<void>((resolve, reject) => {
        let responseBytes = 0; let settled = false
        const finish = (error?: Error) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve() }
        const headers: Record<string, string | number> = {'x-dsh-proxy-assertion': assertion(key, config)}
        if (body.length) { headers['content-type'] = 'application/json'; headers['content-length'] = body.length }
        upstream = http.request({agent: lane.agent, host: 'controller.local', path: clientRequest.url ?? '/', method: clientRequest.method ?? 'GET', headers}, response => {
          const chunks: Buffer[] = []; let overflow = false
          response.on('data', chunk => { responseBytes += chunk.length; if (responseBytes > (config.maxResponseBytes ?? 2 * 1024 * 1024)) { overflow = true; response.removeAllListeners('data'); response.resume(); upstream?.destroy(); finish(new Error('response too large')) } else chunks.push(Buffer.from(chunk)) })
          response.on('end', () => { if (overflow) return; const payload = Buffer.concat(chunks); const safeHeaders: Record<string, string | string[] | number> = {'content-length': payload.length}; for (const name of ['content-type','cache-control','x-content-type-options','x-request-id']) { const value = response.headers[name]; if (value !== undefined) safeHeaders[name] = value }; clientResponse.writeHead(response.statusCode ?? 502, safeHeaders); clientResponse.end(payload); finish() })
          response.on('error', error => finish(error))
        })
        upstream.on('error', finish); clientRequest.once('aborted', () => upstream?.destroy(new Error('client aborted'))); upstream.end(body.length ? body : undefined)
      })
    } catch (error) { if (!clientResponse.destroyed && !clientResponse.writableEnded) fail(clientResponse, (error as {status?: number}).status ?? 502) } finally { clearTimeout(timer) }
  })
  server.headersTimeout = requestTimeoutMs; server.requestTimeout = requestTimeoutMs; server.setTimeout(requestTimeoutMs, socket => socket.destroy())
  try { await bindPrivate(server, config) } catch (error) { for (const lane of lanes) lane.agent.destroy(); throw error }
  let closed = false
  return {server, socketPath: config.socketPath, async close() {
    if (closed) return; closed = true
    for (const lane of lanes) lane.agent.destroy(); server.closeAllConnections()
    await new Promise<void>(resolve => { const timer = setTimeout(resolve, 1_000); timer.unref(); server.close(() => { clearTimeout(timer); resolve() }) })
    await rm(config.socketPath, {force: true})
  }}
}
