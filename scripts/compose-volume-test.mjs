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

try {
  compose('config', '--quiet')
  compose('build')
  // Remove any prior named volumes so Docker's first-use population behavior
  // is exercised, rather than an already-initialized volume.
  compose('down', '-v', '--remove-orphans')
  // Compose has no cross-process create lock: one concurrent caller may lose
  // the harmless container-name race. The successful caller must still leave
  // a recoverable project, and a normal retry must converge to one instance.
  // Both callers may report the same transient create/dependency race even
  // though one of them left a valid project behind.  The authoritative check
  // is the serialized retry below: it must converge and become healthy, or it
  // fails with the real Compose/runtime error.
  await Promise.allSettled([composeAsync('up', '-d'), composeAsync('up', '-d')])
  compose('up', '-d')
  const controller = output('ps', '-q', 'controller')
  const proxy = output('ps', '-q', 'proxy')
  waitFor(() => inspect(controller, '{{.State.Health.Status}}') === 'healthy' && inspect(proxy, '{{.State.Health.Status}}') === 'healthy')
  if (inspect(controller, '{{.Config.User}}') !== '1000:1000' || inspect(proxy, '{{.Config.User}}') !== '1000:1000') throw new Error('runtime service is not unprivileged')
  const capEff = id => execFileSync('docker', ['exec', id, 'sh', '-c', "awk '/^CapEff:/{print $2}' /proc/1/status"], {encoding: 'utf8'}).trim()
  if (capEff(controller) !== '0000000000000000' || capEff(proxy) !== '0000000000000000') throw new Error(`runtime capabilities were not fully dropped: ${capEff(controller)} ${capEff(proxy)}`)
  const controllerRoots = '/var/lib/dsh-docker-services-volume/state /run/dsh-docker-services-volume/socket /var/lib/dsh-audit-checkpoint-volume/data'
  const proxyRoot = '/run/dsh-docker-services-proxy-volume/socket'
  const controllerMetadata = execFileSync('docker', ['compose', '-p', project, '-f', composeFile, '-f', path.join(temp, 'override.yaml'), 'exec', '-T', 'controller', 'sh', '-c', `stat -c '%u:%g:%a:%F' ${controllerRoots}`], {cwd: root, encoding: 'utf8'}).trim().split('\n')
  if (controllerMetadata.some(value => value !== '1000:1000:700:directory')) throw new Error(`unexpected controller volume metadata: ${controllerMetadata}`)
  const proxyMetadata = execFileSync('docker', ['compose', '-p', project, '-f', composeFile, '-f', path.join(temp, 'override.yaml'), 'exec', '-T', 'proxy', 'sh', '-c', `stat -c '%u:%g:%a:%F' ${proxyRoot}`], {cwd: root, encoding: 'utf8'}).trim()
  if (proxyMetadata !== '1000:1000:700:directory') throw new Error(`unexpected proxy volume metadata: ${proxyMetadata}`)
  compose('restart', 'controller')
  waitFor(() => inspect(output('ps', '-q', 'controller'), '{{.State.Health.Status}}') === 'healthy')
  compose('restart', 'proxy')
  waitFor(() => inspect(output('ps', '-q', 'proxy'), '{{.State.Health.Status}}') === 'healthy')
  if (capEff(output('ps', '-q', 'controller')) !== '0000000000000000' || capEff(output('ps', '-q', 'proxy')) !== '0000000000000000') throw new Error('restart restored capabilities')
  console.log('verified absent named volumes, Docker seed population, health, ownership/modes, restart, zero capabilities, and runtime users')
} finally {
  try { compose('down', '-v', '--remove-orphans') } finally { await rm(temp, {recursive: true, force: true}) }
}
