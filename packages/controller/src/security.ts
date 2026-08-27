import { constants, createHash, randomUUID } from 'node:crypto'
import { lstat, mkdir, open, readFile, realpath, rename, stat } from 'node:fs/promises'
import path from 'node:path'
import type { AuthConfig, ControllerConfig } from '@dsh-docker-services/shared'
import {patterns, redact, normalizeMethod, normalizeTarget, proxyProtocolVersion, requestCanonical, responseCanonical, selectedHeaders, sha256Hex, signMac, verifyMac, type RequestBinding, type ResponseBinding} from '@dsh-docker-services/shared'
import {withFileLock} from './file-lock.js'

const fsConstants = (await import('node:fs')).constants
const expectedUid = typeof process.getuid === 'function' ? process.getuid() : undefined
export class SafeError extends Error { constructor(readonly code: 'bad_request' | 'unauthorized' | 'forbidden' | 'not_found' | 'conflict' | 'unavailable' | 'internal', readonly status: number, internalMessage: string) { super(internalMessage) } }
export class ConflictError extends SafeError { constructor(message = 'resource is busy') { super('conflict', 409, message) } }
export function publicMessage(error: SafeError): string { return ({bad_request: 'request rejected', unauthorized: 'authentication required', forbidden: 'operation denied', not_found: 'resource not found', conflict: 'operation already in progress', unavailable: 'controller dependency unavailable', internal: 'controller request failed'} as const)[error.code] }
export function requestId(): string { return randomUUID() }
export function minimalEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv { return {LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin', ...extra} }

async function components(target: string): Promise<string[]> { const normalized = path.resolve(target); const result: string[] = []; let current = normalized; while (current !== path.dirname(current)) { result.unshift(current); current = path.dirname(current) } return result }
export async function assertNoSymlinkComponents(target: string): Promise<void> { for (const component of await components(target)) { try { if ((await lstat(component)).isSymbolicLink()) throw new Error(`symlink path component rejected: ${component}`) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error } } }
export async function ensureOwnedRoot(root: string): Promise<void> { if (!patterns.absolute.test(root)) throw new Error('writable root must be absolute'); await assertNoSymlinkComponents(root); await mkdir(root, {recursive: true, mode: 0o700}); await assertNoSymlinkComponents(root); const info = await lstat(root); if (!info.isDirectory() || info.isSymbolicLink() || (expectedUid !== undefined && info.uid !== expectedUid)) throw new Error(`writable root is not owned by controller uid: ${root}`); if ((info.mode & 0o022) !== 0) throw new Error(`writable root must not be group/world writable: ${root}`) }
export async function assertOwnedRegularFile(file: string, maximumBytes = 64 * 1024): Promise<void> { await assertNoSymlinkComponents(file); const info = await lstat(file); const owned = info.uid === 0 || expectedUid === undefined || info.uid === expectedUid; if (!info.isFile() || info.isSymbolicLink() || info.size > maximumBytes || !owned || (info.mode & 0o022) !== 0) throw new Error(`protected file permissions rejected: ${file}`) }
export async function readProtectedFile(file: string, maximumBytes = 64 * 1024): Promise<Buffer> { await assertOwnedRegularFile(file, maximumBytes); const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW); try { const value = await handle.readFile(); if (value.length > maximumBytes) throw new Error('protected file exceeds size limit'); return value } finally { await handle.close() } }
export async function durableAtomicWrite(target: string, contents: string | Buffer, mode = 0o600): Promise<void> { await assertNoSymlinkComponents(path.dirname(target)); try { if ((await lstat(target)).isSymbolicLink()) throw new Error('symlink write target rejected') } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }; const parent = path.dirname(target); const rootInfo = await lstat(parent); if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || (expectedUid !== undefined && rootInfo.uid !== expectedUid)) throw new Error('unsafe writable parent'); const temporary = path.join(parent, `.${path.basename(target)}.${process.pid}.${randomUUID()}.tmp`); const handle = await open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, mode); try { await handle.writeFile(contents); await handle.sync() } finally { await handle.close() } await rename(temporary, target); const directory = await open(parent, fsConstants.O_RDONLY); try { await directory.sync() } finally { await directory.close() } }

export type AuthenticatedIdentity = { actor: string; role: string; capabilities: ControllerConfig['roles'][number]['capabilities'] }
type Assertion = { iss: string; aud: string; sub: string; role: string; iat: number; exp: number; nonce: string }
export type AuthenticatedRequest = { identity: AuthenticatedIdentity; binding: RequestBinding; digest: string }
export function signControllerProof(key: Buffer, challenge: string): string { return signMac(key, 'handshake', Buffer.from(challenge, 'ascii')) }
class NonceReplayStore {
  private constructor(private readonly root: string, private readonly file: string, private readonly maximumEntries: number) {}
  static async create(root: string, maximumEntries = 10_000): Promise<NonceReplayStore> { await ensureOwnedRoot(root); return new NonceReplayStore(root, path.join(root, 'nonces.json'), maximumEntries) }
  async consume(binding: string, expiresAt: number, now: number): Promise<void> {
    await withFileLock(this.root, 'nonce-replay', {leaseMs: 30_000, waitMs: 5_000}, async () => {
      let values: Record<string, number> = {}
      try {
        const parsed = JSON.parse((await readProtectedFile(this.file, 1024 * 1024)).toString('utf8')) as {version?: unknown; nonces?: unknown}
        if (!parsed.nonces || typeof parsed.nonces !== 'object' || Array.isArray(parsed.nonces)) throw new Error('invalid nonce replay state')
        if (parsed.version === 1) {
          for (const [key, value] of Object.entries(parsed.nonces)) if (!patterns.idempotencyKey.test(key) || !Number.isSafeInteger(value)) throw new Error('invalid legacy nonce replay state')
          // v1 assertions use a different derived MAC key and cannot validate on
          // this protocol. Their replay entries may therefore be safely retired.
        } else if (parsed.version !== 2) throw new Error('invalid nonce replay state')
        else for (const [key, value] of Object.entries(parsed.nonces)) {
          if (!/^[0-9a-f]{64}$/.test(key) || !Number.isSafeInteger(value)) throw new Error('invalid nonce replay state')
          if ((value as number) >= now) values[key] = value as number
        }
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
      if (Object.hasOwn(values, binding)) throw new SafeError('unauthorized', 401, 'proxy request replayed')
      if (Object.keys(values).length >= this.maximumEntries) throw new SafeError('unavailable', 503, 'nonce replay state capacity reached')
      values[binding] = expiresAt
      await durableAtomicWrite(this.file, JSON.stringify({version: 2, nonces: values}))
    })
  }
}
export class HmacProxyAuthenticator {
  private constructor(private readonly config: AuthConfig, private readonly roles: ControllerConfig['roles'], private readonly key: Buffer, private readonly replay: NonceReplayStore) {}
  static async create(config: AuthConfig, roles: ControllerConfig['roles'], replayRoot: string): Promise<HmacProxyAuthenticator> { const key = await readProtectedFile(config.keyFile, 4096); if (key.length < 32) throw new Error('proxy authentication key must contain at least 32 bytes'); return new HmacProxyAuthenticator(config, roles, key, await NonceReplayStore.create(replayRoot)) }
  proveController(challenge: string): string { return signControllerProof(this.key, challenge) }
  private assertion(headers: Record<string, string | string[] | undefined>): {identity: AuthenticatedIdentity; expiresAt: number} {
    if (headers['x-dsh-actor'] !== undefined || headers['x-dsh-role'] !== undefined) throw new SafeError('unauthorized', 401, 'caller identity headers are forbidden')
    const raw = headers['x-dsh-proxy-assertion']; if (typeof raw !== 'string' || raw.length > 4096) throw new SafeError('unauthorized', 401, 'missing proxy assertion')
    const [encoded, signature, extra] = raw.split('.'); if (!encoded || !signature || extra) throw new SafeError('unauthorized', 401, 'malformed proxy assertion')
    if (!verifyMac(this.key, 'assertion', Buffer.from(encoded, 'ascii'), signature)) throw new SafeError('unauthorized', 401, 'invalid proxy signature')
    let assertion: Assertion; try { assertion = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) } catch { throw new SafeError('unauthorized', 401, 'invalid proxy assertion JSON') }
    if (!assertion || typeof assertion !== 'object' || Array.isArray(assertion)) throw new SafeError('unauthorized', 401, 'invalid proxy assertion JSON')
    const now = Math.floor(Date.now() / 1000); const skew = this.config.maxClockSkewSeconds ?? 30
    const validTimes = Number.isFinite(assertion.iat) && Number.isSafeInteger(assertion.iat) && Number.isFinite(assertion.exp) && Number.isSafeInteger(assertion.exp) && assertion.exp > assertion.iat && assertion.exp - assertion.iat <= 300 && assertion.iat >= now - 300 - skew && assertion.iat <= now + skew && assertion.exp >= now - skew && assertion.exp <= now + 300 + skew
    if (assertion.iss !== this.config.issuer || assertion.aud !== this.config.audience || !patterns.identifier.test(assertion.sub) || !patterns.identifier.test(assertion.role) || !patterns.idempotencyKey.test(assertion.nonce) || !validTimes) throw new SafeError('unauthorized', 401, 'proxy assertion claims rejected')
    const role = this.roles.find(candidate => candidate.name === assertion.role); if (!role) throw new SafeError('forbidden', 403, 'unknown authenticated role')
    return {identity: {actor: assertion.sub, role: role.name, capabilities: role.capabilities}, expiresAt: assertion.exp + skew}
  }
  async authenticate(headers: Record<string, string | string[] | undefined>): Promise<AuthenticatedIdentity> {
    const assertion = this.assertion(headers)
    const key = createHash('sha256').update('handshake\0').update(headers['x-dsh-proxy-assertion'] as string).digest('hex')
    await this.replay.consume(key, assertion.expiresAt, Math.floor(Date.now() / 1000))
    return assertion.identity
  }
  async authenticateRequest(headers: Record<string, string | string[] | undefined>, methodInput: string, targetInput: string, rawBody: Buffer): Promise<AuthenticatedRequest> {
    const assertion = this.assertion(headers)
    const version = headers['x-dsh-protocol-version']; const requestId = headers['x-dsh-request-id']; const nonce = headers['x-dsh-request-nonce']; const mac = headers['x-dsh-request-mac']
    if (version !== String(proxyProtocolVersion) || typeof requestId !== 'string' || typeof nonce !== 'string' || typeof mac !== 'string') throw new SafeError('unauthorized', 401, 'missing proxy request binding')
    let method: string; let target: string; let binding: RequestBinding
    try {
      method = normalizeMethod(methodInput); target = normalizeTarget(targetInput)
      const values: Record<string, string | string[] | undefined> = {'content-type': headers['content-type'], 'content-length': headers['content-length']}
      const canonicalHeaders = selectedHeaders(values, ['content-type', 'content-length'])
      const length = canonicalHeaders['content-length']; if (typeof length !== 'string' || !/^(?:0|[1-9][0-9]{0,8})$/.test(length) || Number(length) !== rawBody.length) throw new Error('request length rejected')
      binding = {protocolVersion: proxyProtocolVersion, requestId, nonce, actor: assertion.identity.actor, role: assertion.identity.role, method, target, headers: canonicalHeaders, bodyDigest: sha256Hex(rawBody), bodyLength: rawBody.length}
    } catch { throw new SafeError('unauthorized', 401, 'proxy request binding rejected') }
    const canonical = requestCanonical(binding)
    if (!verifyMac(this.key, 'request', canonical, mac)) throw new SafeError('unauthorized', 401, 'proxy request MAC rejected')
    const digest = sha256Hex(canonical)
    await this.replay.consume(digest, assertion.expiresAt, Math.floor(Date.now() / 1000))
    return {identity: assertion.identity, binding, digest}
  }
  signResponse(request: AuthenticatedRequest, status: number, headers: Record<string, string | undefined>, payload: Buffer): {binding: ResponseBinding; mac: string} {
    const outcome = status >= 200 && status < 300 ? 'ok' : 'error'
    const binding: ResponseBinding = {protocolVersion: proxyProtocolVersion, requestId: request.binding.requestId, nonce: request.binding.nonce, requestDigest: request.digest, status, headers: selectedHeaders(headers, ['content-type', 'content-length', 'cache-control', 'x-content-type-options', 'x-request-id']), bodyDigest: sha256Hex(payload), bodyLength: payload.length, outcome}
    return {binding, mac: signMac(this.key, 'response', responseCanonical(binding))}
  }
}
export function signProxyAssertion(key: Buffer, assertion: Assertion): string { const encoded = Buffer.from(JSON.stringify(assertion)).toString('base64url'); return `${encoded}.${signMac(key, 'assertion', Buffer.from(encoded, 'ascii'))}` }

const commandOperations = new Set(['generic', 'docker', 'deploy-hook', 'secret-test-hook', 'ssh-transport'])
const commandClassifications = new Set(['spawn_error', 'stdin_error', 'nonzero_exit', 'timeout', 'cancelled', 'stdout_limit', 'stderr_limit', 'input_limit'])
function safeCommandDetails(error: unknown): string {
  if (!error || typeof error !== 'object' || !('protectedDetails' in error)) return ''
  const details = (error as {protectedDetails?: unknown}).protectedDetails
  if (!details || typeof details !== 'object' || Array.isArray(details)) return ''
  const value = details as Record<string, unknown>
  const keys = Object.keys(value).sort().join(',')
  const valid = keys === 'classification,correlationId,exitCode,operation,signal,stderrBytes,stdoutBytes' && typeof value.correlationId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.correlationId) && typeof value.operation === 'string' && commandOperations.has(value.operation) && typeof value.classification === 'string' && commandClassifications.has(value.classification) && (value.exitCode === null || (Number.isInteger(value.exitCode) && Number(value.exitCode) >= 0 && Number(value.exitCode) <= 255)) && (value.signal === null || (typeof value.signal === 'string' && /^SIG[A-Z0-9]{1,12}$/.test(value.signal))) && Number.isInteger(value.stdoutBytes) && Number(value.stdoutBytes) >= 0 && Number(value.stdoutBytes) <= 8 * 1024 * 1024 + 1 && Number.isInteger(value.stderrBytes) && Number(value.stderrBytes) >= 0 && Number(value.stderrBytes) <= 64 * 1024 + 1
  return valid ? JSON.stringify(value) : ''
}
async function tightenProtectedLog(file: string): Promise<void> {
  try {
    await assertNoSymlinkComponents(file)
    const handle = await open(file, fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW)
    try { const info = await handle.stat(); if (!info.isFile() || (expectedUid !== undefined && info.uid !== expectedUid)) throw new Error('unsafe protected log file'); await handle.chmod(0o600); await handle.sync() } finally { await handle.close() }
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
}
export class ProtectedLogger {
  private queue = Promise.resolve()
  constructor(private readonly file: string, private readonly maxBytes = 16 * 1024 * 1024) {}
  log(request: string, error: unknown): Promise<void> { const protectedDetails = safeCommandDetails(error); const source = error instanceof Error ? `${error.name}: ${error.message}${protectedDetails ? ` ${protectedDetails}` : ''}` : String(error); const line = JSON.stringify({at: new Date().toISOString(), request, error: redact(source)}) + '\n'; const task = this.queue.then(async () => { await assertNoSymlinkComponents(this.file); await tightenProtectedLog(this.file); await tightenProtectedLog(`${this.file}.1`); try { if ((await lstat(this.file)).size + Buffer.byteLength(line) > this.maxBytes) await rename(this.file, `${this.file}.1`) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }; const handle = await open(this.file, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW, 0o600); try { const info = await handle.stat(); if (!info.isFile() || (expectedUid !== undefined && info.uid !== expectedUid)) throw new Error('unsafe protected log file'); await handle.chmod(0o600); await handle.write(line); await handle.sync() } finally { await handle.close() } }); this.queue = task.catch(() => undefined); return task }
}
