import {randomUUID} from 'node:crypto'
import {constants as fsConstants} from 'node:fs'
import {lstat, open, rename, unlink} from 'node:fs/promises'
import path from 'node:path'
import {patterns} from '@dsh-docker-services/shared'
import {assertNoSymlinkComponents, ConflictError, ensureOwnedRoot, readProtectedFile} from './security.js'

type LockRecord = {version: 1; token: string; ownerPid: number; expiresAt: number; purpose: string; idempotencyKey?: string}
type LockOptions = {leaseMs: number; waitMs?: number; conflictMessage?: string; idempotencyKey?: string}

const expectedUid = typeof process.getuid === 'function' ? process.getuid() : undefined
const pause = (milliseconds: number) => new Promise(resolve => setTimeout(resolve, milliseconds))

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(directory, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
  try { await handle.sync() } finally { await handle.close() }
}

async function readLock(file: string, purpose: string): Promise<LockRecord> {
  const info = await lstat(file)
  if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o600 || (expectedUid !== undefined && info.uid !== expectedUid)) throw new ConflictError('lock integrity check failed')
  let value: unknown
  try { value = JSON.parse((await readProtectedFile(file, 4096)).toString('utf8')) } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw error; throw new ConflictError('lock integrity check failed') }
  const record = value as Partial<LockRecord>
  if (record.version !== 1 || typeof record.token !== 'string' || !/^[0-9a-f-]{36}$/i.test(record.token) || !Number.isSafeInteger(record.ownerPid) || !Number.isSafeInteger(record.expiresAt) || record.purpose !== purpose || (record.idempotencyKey !== undefined && !patterns.idempotencyKey.test(record.idempotencyKey))) throw new ConflictError('lock integrity check failed')
  return record as LockRecord
}

/** Atomic O_EXCL lease used only for fixed controller-owned state paths. */
export async function withFileLock<T>(root: string, purpose: string, options: LockOptions, run: () => Promise<T>): Promise<T> {
  if (!/^[a-z][a-z0-9-]{0,62}$/.test(purpose)) throw new Error('invalid lock purpose')
  if (!Number.isSafeInteger(options.leaseMs) || options.leaseMs < 1_000 || options.leaseMs > 3_600_000) throw new Error('invalid lock lease')
  const waitMs = options.waitMs ?? 0
  if (!Number.isSafeInteger(waitMs) || waitMs < 0 || waitMs > 60_000) throw new Error('invalid lock wait')
  await ensureOwnedRoot(root)
  const target = path.join(root, `${purpose}.lock`)
  await assertNoSymlinkComponents(target)
  const deadline = Date.now() + waitMs
  const token = randomUUID()
  let ownedHandle: Awaited<ReturnType<typeof open>> | undefined
  let ownedRecord: LockRecord | undefined
  let ownedDevice: number | undefined
  let ownedInode: number | bigint | undefined
  for (;;) {
    try {
      const handle = await open(target, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600)
      try {
        const record: LockRecord = {version: 1, token, ownerPid: process.pid, expiresAt: Date.now() + options.leaseMs, purpose, ...(options.idempotencyKey ? {idempotencyKey: options.idempotencyKey} : {})}
        await handle.chmod(0o600); await handle.writeFile(JSON.stringify(record)); await handle.sync()
        const info = await handle.stat(); ownedHandle = handle; ownedRecord = record; ownedDevice = info.dev; ownedInode = info.ino
      } catch (error) { await handle.close(); throw error }
      await syncDirectory(root)
      break
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      let existing: LockRecord
      try { existing = await readLock(target, purpose) } catch (readError) { if ((readError as NodeJS.ErrnoException).code === 'ENOENT') continue; throw readError }
      if (existing.expiresAt <= Date.now()) {
        const before = await lstat(target)
        const stale = path.join(root, `.${purpose}.${randomUUID()}.expired`)
        try {
          const current = await lstat(target)
          if (before.dev !== current.dev || before.ino !== current.ino) continue
          const refreshed = await readLock(target, purpose)
          if (refreshed.token !== existing.token || refreshed.expiresAt > Date.now()) continue
          await rename(target, stale); await syncDirectory(root); await unlink(stale); await syncDirectory(root)
          continue
        } catch (staleError) {
          if (['ENOENT', 'EEXIST'].includes((staleError as NodeJS.ErrnoException).code ?? '')) continue
          throw staleError
        }
      }
      if (Date.now() >= deadline) throw new ConflictError(options.conflictMessage ?? 'lock is active')
      await pause(Math.min(25, Math.max(1, deadline - Date.now())))
    }
  }
  const assertOwnership = async () => { const info = await lstat(target); if (info.dev !== ownedDevice || info.ino !== ownedInode || (await readLock(target, purpose)).token !== token) throw new ConflictError('lock lease was lost') }
  let lost = false
  let renewal = Promise.resolve()
  const renew = setInterval(() => { renewal = renewal.then(async () => { if (!ownedHandle || !ownedRecord) return; await assertOwnership(); ownedRecord.expiresAt = Date.now() + options.leaseMs; const contents = Buffer.from(JSON.stringify(ownedRecord)); await ownedHandle.write(contents, 0, contents.length, 0); await ownedHandle.sync() }).catch(() => { lost = true }) }, Math.max(500, Math.floor(options.leaseMs / 3)))
  renew.unref()
  try { const result = await run(); clearInterval(renew); await renewal; if (lost) throw new ConflictError('lock lease was lost'); await assertOwnership(); return result } finally {
    clearInterval(renew); await renewal; await ownedHandle?.close()
    try {
      const current = await readLock(target, purpose)
      if (current.token === token) { await unlink(target); await syncDirectory(root) }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
    }
  }
}
