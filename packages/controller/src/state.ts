import { createHash, createHmac, randomUUID } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, mkdir, open, rename, unlink } from 'node:fs/promises'
import path from 'node:path'
import type { AuditCheckpoint, AuditEntry, Capability, DeployResult, SecretDefinition } from '@dsh-docker-services/shared'
import { redact } from '@dsh-docker-services/shared'
import { assertNoSymlinkComponents, ConflictError, durableAtomicWrite, ensureOwnedRoot, readProtectedFile } from './security.js'

export class LeaseLockManager {
  constructor(private readonly root: string) {}
  async withLease<T>(name: string, idempotencyKey: string, leaseMs: number, run: () => Promise<T>): Promise<T> {
    const directory = path.join(this.root, 'locks'); await ensureOwnedRoot(directory); const target = path.join(directory, `${name}.lock`); const token = randomUUID()
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try { const handle = await open(target, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600); try { await handle.writeFile(JSON.stringify({token, idempotencyKey, ownerPid: process.pid, expiresAt: Date.now() + leaseMs})); await handle.sync() } finally { await handle.close() }; break } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
        let lock: {expiresAt?: number}; try { lock = JSON.parse((await readProtectedFile(target, 4096)).toString('utf8')) } catch { throw new ConflictError('deployment lock is malformed') }
        if (typeof lock.expiresAt !== 'number' || lock.expiresAt > Date.now()) throw new ConflictError('deployment lease is active')
        const stale = `${target}.expired.${randomUUID()}`; try { await rename(target, stale); await unlink(stale).catch(() => undefined) } catch { continue }
      }
      if (attempt === 2) throw new ConflictError('deployment lock acquisition raced')
    }
    let lost = false
    const renew = setInterval(() => { void (async () => { try { const current = JSON.parse((await readProtectedFile(target, 4096)).toString('utf8')); if (current.token !== token) { lost = true; return } await durableAtomicWrite(target, JSON.stringify({...current, expiresAt: Date.now() + leaseMs})) } catch { lost = true } })() }, Math.max(1000, Math.floor(leaseMs / 3)))
    renew.unref()
    try { const result = await run(); if (lost) throw new ConflictError('deployment lease was lost'); return result } finally { clearInterval(renew); try { const current = JSON.parse((await readProtectedFile(target, 4096)).toString('utf8')); if (current.token === token) await unlink(target) } catch {} }
  }
}

export interface CheckpointSink { read(): Promise<AuditCheckpoint | null>; write(checkpoint: Omit<AuditCheckpoint, 'mac'>): Promise<AuditCheckpoint> }
export class KeyedFileCheckpointSink implements CheckpointSink {
  private constructor(private readonly file: string, private readonly key: Buffer) {}
  static async create(file: string, keyFile: string): Promise<KeyedFileCheckpointSink> { const key = await readProtectedFile(keyFile, 4096); if (key.length < 32) throw new Error('audit checkpoint key must contain at least 32 bytes'); await ensureOwnedRoot(path.dirname(file)); return new KeyedFileCheckpointSink(file, key) }
  private mac(value: Omit<AuditCheckpoint, 'mac'>): string { return createHmac('sha256', this.key).update(JSON.stringify(value)).digest('hex') }
  async read(): Promise<AuditCheckpoint | null> { try { const value = JSON.parse((await readProtectedFile(this.file, 4096)).toString('utf8')) as AuditCheckpoint; const {mac, ...unsigned} = value; if (mac !== this.mac(unsigned)) throw new Error('audit checkpoint authentication failed'); return value } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null; throw error } }
  async write(unsigned: Omit<AuditCheckpoint, 'mac'>): Promise<AuditCheckpoint> { const value = {...unsigned, mac: this.mac(unsigned)}; await durableAtomicWrite(this.file, JSON.stringify(value)); return value }
}

export class AuditLog {
  private queue = Promise.resolve(); private sequence = 0; private previousHash = '0'.repeat(64); private bytes = 0; private healthy = false; private healthReason = 'not initialized'
  private constructor(private readonly file: string, private readonly sink: CheckpointSink) {}
  static async create(root: string, sink: CheckpointSink): Promise<AuditLog> { const directory = path.join(root, 'audit'); await ensureOwnedRoot(directory); const log = new AuditLog(path.join(directory, 'events.jsonl'), sink); await log.initialize(); return log }
  private async initialize(): Promise<void> {
    let body: Buffer<ArrayBufferLike> = Buffer.alloc(0); try { body = await readProtectedFile(this.file, 64 * 1024 * 1024) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    let previous = '0'.repeat(64); let sequence = 0; const hashes = new Map<number, string>()
    try { for (const line of body.toString('utf8').split('\n').filter(Boolean)) { const entry = JSON.parse(line) as AuditEntry; const {hash, ...record} = entry; if (entry.sequence !== sequence + 1 || entry.previousHash !== previous || createHash('sha256').update(JSON.stringify(record)).digest('hex') !== hash) throw new Error('audit chain verification failed'); sequence = entry.sequence; previous = hash; hashes.set(sequence, hash) } } catch { this.healthReason = 'audit truncation or chain corruption detected'; return }
    const checkpoint = await this.sink.read(); if (checkpoint && (body.length < checkpoint.bytes || sequence < checkpoint.sequence || (checkpoint.sequence === 0 ? '0'.repeat(64) : hashes.get(checkpoint.sequence)) !== checkpoint.hash)) { this.healthReason = 'audit truncation or rollback detected'; return }
    if (!checkpoint || checkpoint.sequence < sequence) await this.sink.write({sequence, hash: previous, bytes: body.length, at: new Date().toISOString()})
    this.sequence = sequence; this.previousHash = previous; this.bytes = body.length; this.healthy = true; this.healthReason = 'ok'
  }
  health(): {healthy: boolean; reason: string; sequence: number; bytes: number} { return {healthy: this.healthy, reason: this.healthReason, sequence: this.sequence, bytes: this.bytes} }
  async append(input: Omit<AuditEntry, 'sequence' | 'at' | 'previousHash' | 'hash'>): Promise<void> {
    const task = this.queue.then(async () => { if (!this.healthy) throw new Error(`audit unavailable: ${this.healthReason}`); const record = {sequence: this.sequence + 1, at: new Date().toISOString(), ...input, details: input.details && Object.fromEntries(Object.entries(input.details).map(([key, value]) => [key, redact(value)])), previousHash: this.previousHash}; const hash = createHash('sha256').update(JSON.stringify(record)).digest('hex'); const line = `${JSON.stringify({...record, hash})}\n`; const handle = await open(this.file, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW, 0o600); try { await handle.write(line); await handle.sync() } finally { await handle.close() }; this.sequence = record.sequence; this.previousHash = hash; this.bytes += Buffer.byteLength(line); await this.sink.write({sequence: this.sequence, hash, bytes: this.bytes, at: record.at}) })
    this.queue = task.catch(error => { this.healthy = false; this.healthReason = redact(error instanceof Error ? error.message : String(error)) }); return task
  }
  async read(limit = 100): Promise<AuditEntry[]> { await this.queue; if (!this.healthy) throw new Error(`audit unavailable: ${this.healthReason}`); const entries = (await readProtectedFile(this.file, 64 * 1024 * 1024)).toString('utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line) as AuditEntry); return entries.slice(-Math.max(1, Math.min(1000, limit))) }
}

export class SecretStore {
  constructor(private readonly root: string) {}
  private async target(secret: SecretDefinition): Promise<string> { const target = path.resolve(secret.target); const root = path.resolve(this.root); if (!target.startsWith(`${root}${path.sep}`)) throw new Error('secret target escapes configured root'); await assertNoSymlinkComponents(path.dirname(target)); const parent = path.dirname(target); await ensureOwnedRoot(parent); try { const info = await lstat(target); if (!info.isFile() || info.isSymbolicLink()) throw new Error('secret target must be a regular file') } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error } return target }
  async status(secret: SecretDefinition): Promise<{configured: boolean; updatedAt: string | null}> { const target = await this.target(secret); try { const info = await lstat(target); return {configured: info.isFile() && !info.isSymbolicLink() && info.size > 0, updatedAt: info.mtime.toISOString()} } catch { return {configured: false, updatedAt: null} } }
  async set(secret: SecretDefinition, value: unknown): Promise<void> { if (typeof value !== 'string' || value.length < (secret.minLength ?? 1) || value.length > (secret.maxLength ?? 8192) || value.includes('\0') || (!secret.multiline && /[\r\n]/.test(value))) throw new Error('secret does not meet its configured schema'); await durableAtomicWrite(await this.target(secret), value) }
}
export async function saveDeployment(root: string, service: string, requestKey: string, result: DeployResult): Promise<void> { const directory = path.join(root, 'deployments'); await ensureOwnedRoot(directory); await durableAtomicWrite(path.join(directory, `${service}.json`), JSON.stringify({...result, idempotencyKey: requestKey})) }
export async function readDeployment(root: string, service: string): Promise<(DeployResult & {idempotencyKey: string}) | undefined> { try { return JSON.parse((await readProtectedFile(path.join(root, 'deployments', `${service}.json`), 64 * 1024)).toString('utf8')) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error } }
export function capabilityFor(action: string): Capability { if (action === 'deploy') return 'deploy:execute'; if (action === 'parameters') return 'parameters:write'; if (action === 'secret:status') return 'secrets:status'; if (action.startsWith('secret:')) return action === 'secret:test' ? 'secrets:test' : 'secrets:write'; if (['start', 'stop', 'restart'].includes(action)) return 'services:operate'; return 'services:read' }
