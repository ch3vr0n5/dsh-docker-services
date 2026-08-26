import {createHmac, randomBytes} from 'node:crypto'
import {lstat, mkdir, open, rm} from 'node:fs/promises'
import http, {type IncomingMessage, type ServerResponse} from 'node:http'
import path from 'node:path'
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
}

const absolute = (value: unknown): value is string => typeof value === 'string' && patterns.absolute.test(value) && path.resolve(value) === value
const bounded = (value: unknown, min: number, max: number): value is number => Number.isInteger(value) && Number(value) >= min && Number(value) <= max

function owned(info: {uid: number}): boolean { return typeof process.getuid !== 'function' || info.uid === 0 || info.uid === process.getuid() }

function trustedDirectory(info: {isDirectory(): boolean; isSymbolicLink(): boolean; mode: number; uid: number}): boolean {
  if (!info.isDirectory() || info.isSymbolicLink() || !owned(info)) return false
  if ((info.mode & 0o022) === 0) return true
  // A root-owned sticky directory (for example /tmp) protects its child entries
  // from replacement by other users.  Non-sticky writable ancestors do not.
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

type SocketIdentity = {dev: number; ino: number; uid: number; mode: number}

function socketIdentity(info: {dev: number; ino: number; uid: number; mode: number}): SocketIdentity {
  return {dev: info.dev, ino: info.ino, uid: info.uid, mode: info.mode}
}

function sameSocket(left: SocketIdentity, right: SocketIdentity): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.mode === right.mode
}

async function trustedControllerSocket(file: string, expected?: SocketIdentity): Promise<SocketIdentity> {
  await trustedParents(file)
  const info = await lstat(file)
  if (!info.isSocket() || info.isSymbolicLink() || !owned(info) || (info.mode & 0o022) !== 0) throw new Error('controller socket is insecure')
  const identity = socketIdentity(info)
  if (expected && !sameSocket(identity, expected)) throw new Error('controller socket changed after proxy startup')
  return identity
}

export function parseProxyConfig(value: unknown): ProxyConfig {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid proxy configuration')
  const c = value as Partial<ProxyConfig>
  const expected = ['actor','assertionTtlSeconds','audience','controllerSocketPath','issuer','keyFile','maxRequestBytes','maxResponseBytes','requestTimeoutMs','role','schemaVersion','socketMode','socketPath']
  if (Object.keys(c).some(key => !expected.includes(key))) throw new Error('proxy configuration contains unsupported fields')
  if (c.schemaVersion !== 1 || !absolute(c.socketPath) || !absolute(c.controllerSocketPath) || !absolute(c.keyFile)) throw new Error('proxy paths must be normalized absolute paths')
  if (c.socketPath === c.controllerSocketPath || !patterns.identifier.test(c.issuer ?? '') || !patterns.identifier.test(c.audience ?? '') || !patterns.identifier.test(c.actor ?? '') || !patterns.identifier.test(c.role ?? '')) throw new Error('invalid proxy identity configuration')
  if (c.socketMode !== undefined && ![0o600, 0o660].includes(c.socketMode)) throw new Error('proxy socket mode must be 0600 or 0660')
  if (c.assertionTtlSeconds !== undefined && !bounded(c.assertionTtlSeconds, 5, 300)) throw new Error('invalid assertion TTL')
  if (c.requestTimeoutMs !== undefined && !bounded(c.requestTimeoutMs, 100, 60_000)) throw new Error('invalid proxy timeout')
  if (c.maxRequestBytes !== undefined && !bounded(c.maxRequestBytes, 1024, 1024 * 1024)) throw new Error('invalid request bound')
  if (c.maxResponseBytes !== undefined && !bounded(c.maxResponseBytes, 1024, 8 * 1024 * 1024)) throw new Error('invalid response bound')
  return c as ProxyConfig
}

async function protectedKey(file: string): Promise<Buffer> {
  await trustedParents(file)
  if ((await lstat(file)).isSymbolicLink()) throw new Error('proxy key file is a symlink')
  const handle = await open(file, (await import('node:fs')).constants.O_RDONLY | (await import('node:fs')).constants.O_NOFOLLOW)
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

export async function createProxy(configInput: ProxyConfig): Promise<http.Server> {
  const config = parseProxyConfig(configInput)
  const requestTimeoutMs = config.requestTimeoutMs ?? 15_000
  const key = await protectedKey(config.keyFile)
  await mkdir(path.dirname(config.socketPath), {recursive: true, mode: 0o700})
  await trustedParents(config.socketPath)
  const controllerIdentity = await trustedControllerSocket(config.controllerSocketPath)
  const existing = await lstat(config.socketPath).catch(() => undefined)
  if (existing && (!existing.isSocket() || !owned(existing))) throw new Error('proxy socket path exists and is not an owned socket')
  if (existing) await rm(config.socketPath)
  const server = http.createServer(async (clientRequest, clientResponse) => {
    let upstream: http.ClientRequest | undefined
    let expired = false
    const expire = () => {
      if (expired) return
      expired = true
      const error = Object.assign(new Error('proxy timeout'), {status: 408})
      upstream?.destroy(error)
      clientRequest.destroy(error)
    }
    const timer = setTimeout(expire, requestTimeoutMs); timer.unref()
    try {
      const body = await collect(clientRequest, config.maxRequestBytes ?? 64 * 1024)
      if (expired) return
      await trustedControllerSocket(config.controllerSocketPath, controllerIdentity)
      if (expired) return
      await new Promise<void>((resolve, reject) => {
        let responseBytes = 0; let settled = false
        const finish = (error?: Error) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve() }
        const headers: Record<string, string | number> = {'x-dsh-proxy-assertion': assertion(key, config)}
        if (body.length) { headers['content-type'] = 'application/json'; headers['content-length'] = body.length }
        upstream = http.request({socketPath: config.controllerSocketPath, path: clientRequest.url ?? '/', method: clientRequest.method ?? 'GET', headers}, response => {
          const chunks: Buffer[] = []; let overflow = false
          response.on('data', chunk => {
            responseBytes += chunk.length
            if (responseBytes > (config.maxResponseBytes ?? 2 * 1024 * 1024)) { overflow = true; response.removeAllListeners('data'); response.resume(); upstream?.destroy(); finish(new Error('response too large')) }
            else chunks.push(Buffer.from(chunk))
          })
          response.on('end', () => {
            if (overflow) return
            const payload = Buffer.concat(chunks); const safeHeaders: Record<string, string | string[] | number> = {'content-length': payload.length}
            for (const name of ['content-type','cache-control','x-content-type-options','x-request-id']) { const value = response.headers[name]; if (value !== undefined) safeHeaders[name] = value }
            clientResponse.writeHead(response.statusCode ?? 502, safeHeaders); clientResponse.end(payload); finish()
          })
          response.on('error', error => finish(error))
        })
        upstream.on('error', finish)
        clientRequest.once('aborted', () => upstream?.destroy(new Error('client aborted')))
        if (body.length) upstream.end(body); else upstream.end()
      })
    } catch (error) {
      if (!clientResponse.destroyed && !clientResponse.writableEnded) fail(clientResponse, (error as {status?: number}).status ?? 502)
    } finally { clearTimeout(timer) }
  })
  // Header drips never reach the request callback.  Configure the server-level
  // timeout too, while the per-request deadline above covers an active body.
  server.headersTimeout = requestTimeoutMs
  server.requestTimeout = requestTimeoutMs
  server.setTimeout(requestTimeoutMs, socket => socket.destroy())
  return server
}
