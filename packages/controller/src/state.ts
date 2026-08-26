import { createHash } from 'node:crypto'
import { lstat, mkdir, open, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises'
import path from 'node:path'
import type { AuditEntry, Capability, DeployRequest, SecretDefinition } from '@dsh-docker-services/shared'
import { redact } from '@dsh-docker-services/shared'

export class LockManager {
  constructor(private readonly root: string) {}
  async withLock<T>(name: string, run: () => Promise<T>): Promise<T> { const file = path.join(this.root, 'locks', `${name}.lock`); await mkdir(path.dirname(file), {recursive: true, mode: 0o700}); let handle; try { handle = await open(file, 'wx', 0o600) } catch { throw Object.assign(new Error(`deployment already in progress for ${name}`), {status: 409}) }; try { return await run() } finally { await handle.close(); await unlink(file).catch(() => undefined) } }
}
export class AuditLog {
  constructor(private readonly root: string) {}
  async append(input: Omit<AuditEntry, 'sequence' | 'at' | 'previousHash' | 'hash'>): Promise<void> {
    const file = path.join(this.root, 'audit', 'events.jsonl'); await mkdir(path.dirname(file), {recursive: true, mode: 0o700}); let previous: AuditEntry | undefined
    try { const lines = (await readFile(file, 'utf8')).trim().split('\n').filter(Boolean); previous = lines.length ? JSON.parse(lines[lines.length - 1]!) : undefined } catch {}
    const record = {sequence: (previous?.sequence ?? 0) + 1, at: new Date().toISOString(), ...input, details: input.details && Object.fromEntries(Object.entries(input.details).map(([key, value]) => [key, redact(value)])), previousHash: previous?.hash ?? '0'.repeat(64)}
    const hash = createHash('sha256').update(JSON.stringify(record)).digest('hex'); await writeFile(file, `${JSON.stringify({...record, hash})}\n`, {flag: 'a', mode: 0o600})
  }
  async read(limit = 100): Promise<AuditEntry[]> { const file = path.join(this.root, 'audit', 'events.jsonl'); try { const entries = (await readFile(file, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line) as AuditEntry); let previous = '0'.repeat(64); for (const entry of entries) { const {hash, ...record} = entry; if (entry.previousHash !== previous || createHash('sha256').update(JSON.stringify(record)).digest('hex') !== hash) throw new Error('audit chain verification failed'); previous = hash } return entries.slice(-Math.max(1, Math.min(1000, limit))) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []; throw error } }
}
export class SecretStore {
  constructor(private readonly root: string) {}
  private target(secret: SecretDefinition): string { const target = path.resolve(secret.target); const root = path.resolve(this.root); if (!target.startsWith(`${root}${path.sep}`)) throw new Error('secret target escapes configured root'); return target }
  async status(secret: SecretDefinition): Promise<{configured: boolean; updatedAt: string | null}> { try { const info = await lstat(this.target(secret)); return {configured: info.isFile() && !info.isSymbolicLink() && info.size > 0, updatedAt: info.mtime.toISOString()} } catch { return {configured: false, updatedAt: null} } }
  async set(secret: SecretDefinition, value: unknown): Promise<void> { if (typeof value !== 'string' || value.length < (secret.minLength ?? 1) || value.length > (secret.maxLength ?? 8192) || value.includes('\0') || (!secret.multiline && /[\r\n]/.test(value))) throw new Error('secret does not meet its configured schema'); const target = this.target(secret); await mkdir(path.dirname(target), {recursive: true, mode: 0o700}); const temporary = `${target}.${process.pid}.${Date.now()}.tmp`; await writeFile(temporary, value, {mode: 0o600, flag: 'wx'}); await rename(temporary, target) }
}
export async function saveDeployment(root: string, service: string, request: DeployRequest): Promise<void> { const directory = path.join(root, 'deployments'); await mkdir(directory, {recursive: true, mode: 0o700}); const target = path.join(directory, `${service}.json`); const document = { ...request, deployedAt: new Date().toISOString() }; await writeFile(`${target}.tmp`, JSON.stringify(document), {mode: 0o600}); await rename(`${target}.tmp`, target) }
export async function readDeployment(root: string, service: string): Promise<any> { try { return JSON.parse(await readFile(path.join(root, 'deployments', `${service}.json`), 'utf8')) } catch { return undefined } }
export function capabilityFor(action: string): Capability { if (action === 'deploy') return 'deploy:execute'; if (action === 'parameters') return 'parameters:write'; if (action === 'secret:status') return 'secrets:status'; if (action.startsWith('secret:')) return action === 'secret:test' ? 'secrets:test' : 'secrets:write'; if (['start', 'stop', 'restart'].includes(action)) return 'services:operate'; return 'services:read' }
