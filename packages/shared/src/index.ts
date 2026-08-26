/** Versioned protocol shared by the unprivileged plugin and privileged controller. */
export const protocolVersion = 1 as const
export const serviceActions = ['inventory', 'logs', 'health', 'start', 'stop', 'restart', 'deploy', 'parameters:write', 'secret:set', 'secret:rotate', 'secret:test', 'secret:status'] as const
export const capabilities = ['services:read', 'services:operate', 'deploy:execute', 'parameters:write', 'secrets:status', 'secrets:write', 'secrets:test', 'audit:read'] as const
export type ServiceAction = typeof serviceActions[number]
export type Capability = typeof capabilities[number]
export type TestState = 'passed' | 'failed'
export type Parameter = { key: string; label: string; description?: string; type: 'string' | 'integer' | 'boolean' | 'enum'; default?: string; enum?: string[]; pattern?: string; required?: boolean }
export type DeployPolicy = { hook: string; repositories: string[]; branches: string[]; timeoutMs?: number; leaseMs?: number }
export type SecretDefinition = { id: string; label: string; target: string; description?: string; minLength?: number; maxLength?: number; multiline?: boolean; testHook?: string }
export type ServiceDefinition = { name: string; displayName?: string; containers: string[]; actions: ServiceAction[]; url?: string; parameters?: Parameter[]; deploy?: DeployPolicy; secrets?: SecretDefinition[] }
export type RoleDefinition = { name: string; capabilities: Capability[] }
export type DockerConfig = {
  kind: 'local' | 'ssh' | 'tls'; binary: string; host: string
  ssh?: { binary: string; host: string; user: string; port?: number; knownHosts: string; identityFile?: string; helper: string; timeoutMs?: number; maxOutputBytes?: number }
  tls?: { url: string; caFile: string; certFile: string; keyFile: string; serverName?: string; timeoutMs?: number; maxOutputBytes?: number }
}
export type AuthConfig = { kind: 'hmac-proxy'; keyFile: string; issuer: string; audience: string; maxClockSkewSeconds?: number }
export type AuditConfig = { checkpointFile: string; checkpointKeyFile: string }
export type ControllerConfig = { schemaVersion: 1; instance: string; docker: DockerConfig; auth: AuthConfig; audit: AuditConfig; services: ServiceDefinition[]; roles: RoleDefinition[]; stateDir: string; secretRoot: string; socketPath: string; socketMode?: number }
export type ContainerView = { name: string; image: string; imageDigest: string | null; status: string; health: string | null; startedAt: string | null; resources: { cpuPercent: number | null; memoryBytes: number | null }; controlled: boolean }
export type DeployRequest = { repo: string; branch: string; sha: string; idempotencyKey: string }
export type DeployResult = { repo: string; branch: string; sha: string; imageDigest: string; deployedAt: string; testState: TestState; reachable: true; branchVerified: true }
export type DeploymentView = Omit<DeployResult, 'reachable' | 'branchVerified'> & { url: string | null }
export type ServiceView = { name: string; displayName: string; actions: ServiceAction[]; containers: ContainerView[]; parameters: Array<Parameter & { value?: string }>; deployment: DeploymentView | null; health: 'healthy' | 'degraded' | 'unknown' }
export type Inventory = { protocolVersion: 1; instance: string; generatedAt: string; services: ServiceView[]; unmanaged: ContainerView[] }
export type AuditEntry = { sequence: number; at: string; actor: string; capability: Capability; action: string; service?: string; secret?: string; outcome: 'ok' | 'denied' | 'error'; details?: Record<string, string>; previousHash: string; hash: string }
export type AuditCheckpoint = { sequence: number; hash: string; bytes: number; at: string; mac: string }
export type PublicError = { error: { code: 'bad_request' | 'unauthorized' | 'forbidden' | 'not_found' | 'conflict' | 'unavailable' | 'internal'; message: string; requestId: string } }

export const patterns = { identifier: /^[a-z][a-z0-9-]{0,62}$/, revision: /^[0-9a-f]{40}$/i, digest: /^sha256:[0-9a-f]{64}$/i, idempotencyKey: /^[A-Za-z0-9._:-]{16,128}$/, absolute: /^\/(?!.*\/\.\.?\/)/ } as const
function boundedInteger(value: unknown, minimum: number, maximum: number): boolean { return Number.isInteger(value) && Number(value) >= minimum && Number(value) <= maximum }
export function assertConfig(value: unknown): asserts value is ControllerConfig {
  const c = value as Partial<ControllerConfig>
  if (!c || c.schemaVersion !== 1 || typeof c.instance !== 'string' || !patterns.identifier.test(c.instance) || !Array.isArray(c.services) || !Array.isArray(c.roles) || !c.docker || !c.auth || !c.audit) throw new Error('invalid controller configuration')
  for (const item of [c.stateDir, c.secretRoot, c.socketPath, c.docker.binary, c.auth.keyFile, c.audit.checkpointFile, c.audit.checkpointKeyFile]) if (typeof item !== 'string' || !patterns.absolute.test(item)) throw new Error('configuration paths must be normalized absolute paths')
  if (c.socketMode !== undefined && ![0o600, 0o660].includes(c.socketMode)) throw new Error('socket mode must be 0600 or 0660')
  if (c.auth.kind !== 'hmac-proxy' || !patterns.identifier.test(c.auth.issuer) || !patterns.identifier.test(c.auth.audience) || (c.auth.maxClockSkewSeconds !== undefined && !boundedInteger(c.auth.maxClockSkewSeconds, 1, 300))) throw new Error('invalid authentication configuration')
  if (!['local', 'ssh', 'tls'].includes(c.docker.kind) || !c.docker.host.startsWith('unix:///')) throw new Error('Docker host must be an explicit unix socket')
  if (c.docker.kind === 'ssh' && (!c.docker.ssh || !patterns.absolute.test(c.docker.ssh.binary) || !patterns.absolute.test(c.docker.ssh.helper) || !patterns.absolute.test(c.docker.ssh.knownHosts) || (c.docker.ssh.identityFile !== undefined && !patterns.absolute.test(c.docker.ssh.identityFile)) || (c.docker.ssh.port !== undefined && !boundedInteger(c.docker.ssh.port, 1, 65535)) || (c.docker.ssh.timeoutMs !== undefined && !boundedInteger(c.docker.ssh.timeoutMs, 100, 3_600_000)) || (c.docker.ssh.maxOutputBytes !== undefined && !boundedInteger(c.docker.ssh.maxOutputBytes, 1024, 8 * 1024 * 1024)))) throw new Error('invalid SSH adapter configuration')
  if (c.docker.kind === 'tls' && (!c.docker.tls || !c.docker.tls.url.startsWith('https://') || !patterns.absolute.test(c.docker.tls.caFile) || !patterns.absolute.test(c.docker.tls.certFile) || !patterns.absolute.test(c.docker.tls.keyFile) || (c.docker.tls.timeoutMs !== undefined && !boundedInteger(c.docker.tls.timeoutMs, 100, 3_600_000)) || (c.docker.tls.maxOutputBytes !== undefined && !boundedInteger(c.docker.tls.maxOutputBytes, 1024, 8 * 1024 * 1024)))) throw new Error('invalid TLS adapter configuration')
  const names = new Set<string>()
  for (const role of c.roles) if (!patterns.identifier.test(role.name) || role.capabilities.some(capability => !capabilities.includes(capability))) throw new Error('invalid role definition')
  for (const service of c.services) {
    if (!service || !patterns.identifier.test(service.name) || names.has(service.name) || !Array.isArray(service.containers) || !Array.isArray(service.actions)) throw new Error('invalid service definition')
    names.add(service.name)
    if (!service.containers.length || service.containers.some(name => !patterns.identifier.test(name)) || service.actions.some(action => !serviceActions.includes(action))) throw new Error(`invalid service allowlist: ${service.name}`)
    for (const parameter of service.parameters ?? []) if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(parameter.key) || !['string', 'integer', 'boolean', 'enum'].includes(parameter.type) || (parameter.type === 'enum' && !parameter.enum?.length)) throw new Error(`invalid parameter: ${parameter.key}`)
    if (service.url && !/^https?:\/\//.test(service.url)) throw new Error(`invalid service URL: ${service.name}`)
    if (service.deploy && (!patterns.absolute.test(service.deploy.hook) || !service.deploy.repositories.length || !service.deploy.branches.length || (service.deploy.timeoutMs !== undefined && !boundedInteger(service.deploy.timeoutMs, 1000, 3_600_000)) || (service.deploy.leaseMs !== undefined && !boundedInteger(service.deploy.leaseMs, 3000, 3_600_000)))) throw new Error(`invalid deploy policy: ${service.name}`)
    for (const secret of service.secrets ?? []) if (!patterns.identifier.test(secret.id) || !patterns.absolute.test(secret.target) || !secret.target.startsWith(`${c.secretRoot}/`) || (secret.testHook && !patterns.absolute.test(secret.testHook)) || (secret.minLength !== undefined && !boundedInteger(secret.minLength, 1, 8192)) || (secret.maxLength !== undefined && !boundedInteger(secret.maxLength, secret.minLength ?? 1, 8192))) throw new Error(`invalid secret: ${secret.id}`)
  }
}
export function assertDeployRequest(value: unknown): asserts value is DeployRequest {
  const request = value as Partial<DeployRequest>
  if (!request || Object.keys(request).sort().join(',') !== 'branch,idempotencyKey,repo,sha' || typeof request.repo !== 'string' || request.repo.length > 2048 || typeof request.branch !== 'string' || request.branch.length > 255 || typeof request.sha !== 'string' || !patterns.revision.test(request.sha) || typeof request.idempotencyKey !== 'string' || !patterns.idempotencyKey.test(request.idempotencyKey)) throw new Error('invalid exact-revision deployment request')
}
export function assertDeployResult(value: unknown, request: DeployRequest): asserts value is DeployResult {
  const result = value as Partial<DeployResult>
  if (!result || result.repo !== request.repo || result.branch !== request.branch || result.sha?.toLowerCase() !== request.sha.toLowerCase() || !patterns.digest.test(result.imageDigest ?? '') || result.testState !== 'passed' || result.reachable !== true || result.branchVerified !== true || typeof result.deployedAt !== 'string' || Number.isNaN(Date.parse(result.deployedAt))) throw new Error('deploy hook returned untrusted or incomplete metadata')
}
export function redact(text: string): string { return text.slice(0, 16_384).replace(/(authorization|bearer|token|secret|password|api[-_]?key)(\s*[:=]?\s*)[^\s,;"']+/gi, '$1$2[REDACTED]').replace(/[A-Za-z0-9+/=_-]{40,}/g, '[REDACTED-LONG-VALUE]') }
