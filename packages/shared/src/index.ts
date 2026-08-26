/** The versioned, intentionally small protocol shared by the unprivileged plugin and controller. */
export const protocolVersion = 1 as const
export const serviceActions = ['inventory', 'logs', 'health', 'start', 'stop', 'restart', 'deploy', 'parameters:write', 'secret:set', 'secret:rotate', 'secret:test', 'secret:status'] as const
export type ServiceAction = typeof serviceActions[number]
export type Capability = 'services:read' | 'services:operate' | 'deploy:execute' | 'parameters:write' | 'secrets:status' | 'secrets:write' | 'secrets:test' | 'audit:read'
export type Parameter = { key: string; label: string; description?: string; type: 'string' | 'integer' | 'boolean' | 'enum'; default?: string; enum?: string[]; pattern?: string; required?: boolean }
export type DeployPolicy = { hook: string; repositories: string[]; branches: string[]; requireImageDigest?: boolean }
export type SecretDefinition = { id: string; label: string; target: string; description?: string; minLength?: number; maxLength?: number; multiline?: boolean; testHook?: string }
export type ServiceDefinition = { name: string; displayName?: string; containers: string[]; actions: ServiceAction[]; url?: string; parameters?: Parameter[]; deploy?: DeployPolicy; secrets?: SecretDefinition[] }
export type RoleDefinition = { name: string; capabilities: Capability[] }
export type ControllerConfig = { schemaVersion: 1; instance: string; docker: { kind: 'local' | 'ssh' | 'tls'; socketPath?: string; ssh?: { host: string; user: string; port?: number; knownHosts: string; identityFile?: string; helper: string }; tls?: { url: string; caFile: string; certFile: string; keyFile: string } }; services: ServiceDefinition[]; roles: RoleDefinition[]; stateDir: string; secretRoot: string }
export type ContainerView = { name: string; image: string; imageDigest: string | null; status: string; health: string | null; startedAt: string | null; resources: { cpuPercent: number | null; memoryBytes: number | null }; controlled: boolean }
export type DeploymentView = { repo: string | null; branch: string | null; sha: string | null; imageDigest: string | null; deployedAt: string | null; testState: 'unknown' | 'passed' | 'failed'; url: string | null }
export type ServiceView = { name: string; displayName: string; actions: ServiceAction[]; containers: ContainerView[]; parameters: Array<Parameter & { value?: string }>; deployment: DeploymentView; health: 'healthy' | 'degraded' | 'unknown' }
export type Inventory = { protocolVersion: 1; instance: string; generatedAt: string; services: ServiceView[]; unmanaged: ContainerView[] }
export type AuditEntry = { sequence: number; at: string; actor: string; capability: Capability; action: string; service?: string; secret?: string; outcome: 'ok' | 'denied' | 'error'; details?: Record<string, string>; previousHash: string; hash: string }
export type DeployRequest = { repo: string; branch: string; sha: string; imageDigest?: string; testState?: 'passed' | 'failed' | 'unknown' }

const identifier = /^[a-z][a-z0-9-]{0,62}$/
const revision = /^[0-9a-f]{7,64}$/i
const digest = /^sha256:[0-9a-f]{64}$/i
const absolute = /^\/(?!.*\/\.\.?\/)/
export function assertConfig(value: unknown): asserts value is ControllerConfig {
  const c = value as Partial<ControllerConfig>
  if (!c || c.schemaVersion !== 1 || typeof c.instance !== 'string' || !identifier.test(c.instance) || !Array.isArray(c.services) || !Array.isArray(c.roles) || !c.docker || !['local', 'ssh', 'tls'].includes(c.docker.kind ?? '') || typeof c.stateDir !== 'string' || !absolute.test(c.stateDir) || typeof c.secretRoot !== 'string' || !absolute.test(c.secretRoot)) throw new Error('invalid controller configuration')
  const names = new Set<string>()
  for (const service of c.services) {
    if (!service || !identifier.test(service.name) || names.has(service.name) || !Array.isArray(service.containers) || !Array.isArray(service.actions)) throw new Error('invalid service definition')
    names.add(service.name)
    if (service.containers.some(name => !identifier.test(name)) || service.actions.some(action => !serviceActions.includes(action))) throw new Error(`invalid service allowlist: ${service.name}`)
    for (const parameter of service.parameters ?? []) if (!identifier.test(parameter.key) || !['string', 'integer', 'boolean', 'enum'].includes(parameter.type) || (parameter.type === 'enum' && !(parameter.enum?.length))) throw new Error(`invalid parameter: ${parameter.key}`)
    if (service.deploy && (!absolute.test(service.deploy.hook) || !service.deploy.repositories.length || !service.deploy.branches.length)) throw new Error(`invalid deploy policy: ${service.name}`)
    for (const secret of service.secrets ?? []) if (!identifier.test(secret.id) || !absolute.test(secret.target) || (secret.testHook && !absolute.test(secret.testHook))) throw new Error(`invalid secret: ${secret.id}`)
  }
}
export function assertDeployRequest(value: unknown): asserts value is DeployRequest {
  const request = value as Partial<DeployRequest>
  if (!request || typeof request.repo !== 'string' || typeof request.branch !== 'string' || typeof request.sha !== 'string' || !revision.test(request.sha) || (request.imageDigest !== undefined && !digest.test(request.imageDigest)) || (request.testState !== undefined && !['passed', 'failed', 'unknown'].includes(request.testState))) throw new Error('invalid exact-revision deployment request')
}
export function redact(text: string): string { return text.replace(/(token|secret|password|authorization|bearer)[^\s,;]*/gi, '$1=[REDACTED]') }
