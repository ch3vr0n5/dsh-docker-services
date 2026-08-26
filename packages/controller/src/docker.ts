import { execFile, spawn } from 'node:child_process'
import { promisify } from 'node:util'
import { readFile } from 'node:fs/promises'
import https from 'node:https'
import type { ContainerView, ControllerConfig, DeployRequest, ServiceDefinition } from '@dsh-docker-services/shared'

const exec = promisify(execFile)
const inspectFormat = '{{json .}}'
export interface DockerAdapter { inventory(): Promise<ContainerView[]>; action(service: ServiceDefinition, action: 'start' | 'stop' | 'restart'): Promise<void>; logs(service: ServiceDefinition, tail: number): Promise<string>; deploy(service: ServiceDefinition, request: DeployRequest): Promise<void> }
export async function fixedCommand(file: string, args: string[], timeout = 15 * 60_000): Promise<string> {
  const result = await exec(file, args, { timeout, maxBuffer: 8 * 1024 * 1024, windowsHide: true })
  return result.stdout
}
function normalize(raw: any): ContainerView {
  const state = raw.State ?? {}; const config = raw.Config ?? {}; const labels = config.Labels ?? {}
  const image = String(config.Image ?? raw.Image ?? '')
  return { name: String(raw.Name ?? '').replace(/^\//, ''), image, imageDigest: typeof raw.RepoDigests?.[0] === 'string' ? raw.RepoDigests[0] : null, status: String(state.Status ?? 'unknown'), health: typeof state.Health?.Status === 'string' ? state.Health.Status : null, startedAt: typeof state.StartedAt === 'string' ? state.StartedAt : null, resources: { cpuPercent: null, memoryBytes: null }, controlled: false }
}
export class LocalDockerAdapter implements DockerAdapter {
  constructor(private readonly docker = 'docker') {}
  async inventory(): Promise<ContainerView[]> {
    const ids = (await fixedCommand(this.docker, ['ps', '--all', '--quiet'])).trim().split(/\s+/).filter(Boolean)
    if (!ids.length) return []
    const raw = JSON.parse(await fixedCommand(this.docker, ['inspect', ...ids]))
    return raw.map(normalize)
  }
  async action(service: ServiceDefinition, action: 'start' | 'stop' | 'restart'): Promise<void> { await fixedCommand(this.docker, [action, ...service.containers]) }
  async logs(service: ServiceDefinition, tail: number): Promise<string> { return fixedCommand(this.docker, ['logs', '--tail', String(tail), service.containers[0]!]) }
  async deploy(service: ServiceDefinition, request: DeployRequest): Promise<void> {
    if (!service.deploy) throw new Error('deployment is not configured')
    await fixedCommand(service.deploy.hook, ['--service', service.name, '--repo', request.repo, '--branch', request.branch, '--sha', request.sha, ...(request.imageDigest ? ['--image-digest', request.imageDigest] : [])], 30 * 60_000)
  }
}
export type RemoteCall = { operation: 'inventory' | 'action' | 'logs' | 'deploy'; service?: string; action?: string; tail?: number; deployment?: DeployRequest }
export interface RemoteTransport { call(request: RemoteCall): Promise<unknown> }
/** Fixed-command SSH JSON transport. The helper is provisioned by an administrator, not supplied by a caller. */
export class SshJsonTransport implements RemoteTransport {
  constructor(private readonly config: NonNullable<ControllerConfig['docker']['ssh']>) {}
  call(request: RemoteCall): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!/^[a-zA-Z0-9.-]+$/.test(this.config.host) || !/^[a-z_][a-z0-9_-]*$/i.test(this.config.user) || !this.config.helper.startsWith('/')) return reject(new Error('invalid constrained SSH configuration'))
      const args = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=${this.config.knownHosts}`, '-p', String(this.config.port ?? 22), '-l', this.config.user, ...(this.config.identityFile ? ['-i', this.config.identityFile] : []), this.config.host, this.config.helper]
      const child = spawn('ssh', args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true }); const out: Buffer[] = []; const err: Buffer[] = []
      child.stdout.on('data', chunk => out.push(Buffer.from(chunk))); child.stderr.on('data', chunk => err.push(Buffer.from(chunk)))
      child.on('error', reject); child.on('close', code => { try { const response = JSON.parse(Buffer.concat(out).toString('utf8')); if (code !== 0 || response.ok === false) reject(new Error(response.error ?? Buffer.concat(err).toString('utf8') ?? 'remote adapter failed')); else resolve(response.value ?? response) } catch { reject(new Error('remote SSH adapter returned invalid JSON')) } })
      child.stdin.end(JSON.stringify(request))
    })
  }
}
/** mTLS transport accepts only a configured endpoint; it does not proxy user-provided URLs. */
export class TlsJsonTransport implements RemoteTransport {
  constructor(private readonly config: NonNullable<ControllerConfig['docker']['tls']>) {}
  async call(request: RemoteCall): Promise<unknown> {
    const url = new URL(this.config.url); if (url.protocol !== 'https:') throw new Error('TLS adapter requires https')
    const [ca, cert, key] = await Promise.all([readFile(this.config.caFile), readFile(this.config.certFile), readFile(this.config.keyFile)])
    return new Promise((resolve, reject) => { const payload = JSON.stringify(request); const req = https.request(url, { method: 'POST', ca, cert, key, rejectUnauthorized: true, headers: {'content-type': 'application/json', 'content-length': Buffer.byteLength(payload)} }, res => { const chunks: Buffer[] = []; res.on('data', value => chunks.push(Buffer.from(value))); res.on('end', () => { try { const body = JSON.parse(Buffer.concat(chunks).toString('utf8')); if ((res.statusCode ?? 500) >= 400 || body.ok === false) reject(new Error(body.error ?? 'remote adapter rejected request')); else resolve(body.value ?? body) } catch { reject(new Error('remote TLS adapter returned invalid JSON')) } }) }); req.on('error', reject); req.end(payload) })
  }
}
export class RemoteDockerAdapter implements DockerAdapter {
  constructor(private readonly transport: RemoteTransport) {}
  async inventory(): Promise<ContainerView[]> { return await this.transport.call({operation: 'inventory'}) as ContainerView[] }
  async action(service: ServiceDefinition, action: 'start' | 'stop' | 'restart'): Promise<void> { await this.transport.call({operation: 'action', service: service.name, action}) }
  async logs(service: ServiceDefinition, tail: number): Promise<string> { const value = await this.transport.call({operation: 'logs', service: service.name, tail}); return String((value as {logs?: string}).logs ?? value) }
  async deploy(service: ServiceDefinition, request: DeployRequest): Promise<void> { await this.transport.call({operation: 'deploy', service: service.name, deployment: request}) }
}
