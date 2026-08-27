import {execFileSync, spawn} from 'node:child_process'
import {mkdtemp, rm, writeFile} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import {randomBytes} from 'node:crypto'

const root = path.resolve(new URL('..', import.meta.url).pathname)
const composeFile = path.join(root, 'examples/container/compose.yaml')
const temp = await mkdtemp(path.join(os.tmpdir(), 'dsh-compose-volume-'))
const project = `dshvolumetest${process.pid}${Date.now().toString(36)}`.replace(/[^a-z0-9]/g, '').slice(0, 55)
const compose = (...args) => execFileSync('docker', ['compose', '-p', project, '-f', composeFile, '-f', path.join(temp, 'override.yaml'), ...args], {cwd: root, stdio: 'inherit'})
const output = (...args) => execFileSync('docker', ['compose', '-p', project, '-f', composeFile, '-f', path.join(temp, 'override.yaml'), ...args], {cwd: root, encoding: 'utf8'}).trim()
const composeAsync = (...args) => new Promise((resolve, reject) => {
  const child = spawn('docker', ['compose', '-p', project, '-f', composeFile, '-f', path.join(temp, 'override.yaml'), ...args], {cwd: root, stdio: 'inherit'})
  child.once('error', reject)
  child.once('exit', code => code === 0 ? resolve() : reject(new Error(`Compose exited with ${code}`)))
})
const inspect = (id, format) => execFileSync('docker', ['inspect', '--format', format, id], {encoding: 'utf8'}).trim()
const waitFor = (check, timeout = 90_000) => {
  const started = Date.now()
  while (Date.now() - started < timeout) {
    try { if (check()) return } catch {}
    execFileSync('sleep', ['1'])
  }
  throw new Error('timed out waiting for Compose services')
}

const auth = path.join(temp, 'proxy-auth.key')
const checkpoint = path.join(temp, 'audit-checkpoint.key')
await writeFile(auth, randomBytes(64), {mode: 0o600})
await writeFile(checkpoint, randomBytes(64), {mode: 0o600})
await writeFile(path.join(temp, 'override.yaml'), `secrets:\n  proxy-auth-key:\n    file: ${JSON.stringify(auth)}\n  audit-checkpoint-key:\n    file: ${JSON.stringify(checkpoint)}\n`)

let initId
try {
  compose('config', '--quiet')
  compose('build')
  // Compose has no cross-process create lock: one concurrent caller may lose
  // the harmless container-name race. The successful caller must still leave
  // a recoverable project, and a normal retry must converge to one instance.
  const attempts = await Promise.allSettled([composeAsync('up', '-d'), composeAsync('up', '-d')])
  if (!attempts.some(attempt => attempt.status === 'fulfilled')) throw new Error('all concurrent Compose startups failed')
  compose('up', '-d')
  waitFor(() => {
    initId = output('ps', '-a', '-q', 'volume-init')
    return Boolean(initId) && inspect(initId, '{{.State.Status}} {{.State.ExitCode}}') === 'exited 0'
  })
  const controller = output('ps', '-q', 'controller')
  const proxy = output('ps', '-q', 'proxy')
  waitFor(() => inspect(controller, '{{.State.Health.Status}}') === 'healthy' && inspect(proxy, '{{.State.Health.Status}}') === 'healthy')
  if (inspect(initId, '{{.Config.User}}') !== '0:0') throw new Error('volume-init did not run as root')
  if (inspect(controller, '{{.Config.User}}') !== '1000:1000' || inspect(proxy, '{{.Config.User}}') !== '1000:1000') throw new Error('runtime service is not unprivileged')
  const controllerRoots = '/var/lib/dsh-docker-services /run/dsh-docker-services /var/lib/dsh-audit-checkpoint'
  const proxyRoot = '/run/dsh-docker-services-proxy'
  const controllerMetadata = execFileSync('docker', ['compose', '-p', project, '-f', composeFile, '-f', path.join(temp, 'override.yaml'), 'exec', '-T', 'controller', 'sh', '-c', `stat -c '%u:%g:%a:%F' ${controllerRoots}`], {cwd: root, encoding: 'utf8'}).trim().split('\n')
  if (controllerMetadata.some(value => value !== '1000:1000:700:directory')) throw new Error(`unexpected controller volume metadata: ${controllerMetadata}`)
  const proxyMetadata = execFileSync('docker', ['compose', '-p', project, '-f', composeFile, '-f', path.join(temp, 'override.yaml'), 'exec', '-T', 'proxy', 'sh', '-c', `stat -c '%u:%g:%a:%F' ${proxyRoot}`], {cwd: root, encoding: 'utf8'}).trim()
  if (proxyMetadata !== '1000:1000:700:directory') throw new Error(`unexpected proxy volume metadata: ${proxyMetadata}`)
  compose('restart', 'controller')
  waitFor(() => inspect(output('ps', '-q', 'controller'), '{{.State.Health.Status}}') === 'healthy')
  compose('restart', 'proxy')
  waitFor(() => inspect(output('ps', '-q', 'proxy'), '{{.State.Health.Status}}') === 'healthy')
  if (inspect(initId, '{{.State.Status}} {{.State.ExitCode}}') !== 'exited 0') throw new Error('volume-init changed after restart')
  console.log('verified clean named-volume init, health, ownership/modes, restart, and runtime users')
} finally {
  try { compose('down', '-v', '--remove-orphans') } finally { await rm(temp, {recursive: true, force: true}) }
}
