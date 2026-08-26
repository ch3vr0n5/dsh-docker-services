import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-client-connection'
import type {} from '@deepseek-ai/dsh-tools'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { contained, UnixSocketTransport } from './client.js'

export const name = 'dsh-docker-services'
export const inject = ['connection', 'tools']
export interface Config { socketPath: string }
export const Config: z<Config> = z.object({socketPath: z.string().default('/run/dsh-docker-services/proxy.sock')}).default({socketPath: '/run/dsh-docker-services/proxy.sock'})
const encode = encodeURIComponent
export function apply(ctx: Context, config: Config): void {
  const transport = new UnixSocketTransport(config.socketPath)
  const call = (route: string, options?: {method?: string; body?: unknown; signal?: AbortSignal}): any => contained(transport.request(route, options))
  ctx.connection.rpc.handle('/dsh-docker-services', async (endpoint, payload, signal) => {
    const input = payload && typeof payload === 'object' ? payload as Record<string, unknown> : {}; const service = typeof input.service === 'string' ? input.service : ''
    if (endpoint === 'inventory') return call('/v1/services', {signal})
    if (endpoint === 'health') return call('/v1/health', {signal})
    if (!service) return {ok: false as const, error: {code: 'internal' as const, message: 'service is required', details: {}}}
    if (endpoint === 'logs') return call(`/v1/services/${encode(service)}/logs?tail=${Math.max(1, Math.min(1000, Number(input.tail) || 200))}`, {signal})
    if (['start', 'stop', 'restart', 'deploy', 'parameters'].includes(endpoint)) return call(`/v1/services/${encode(service)}/${endpoint}`, {method: 'POST', body: endpoint === 'parameters' ? {values: input.values} : endpoint === 'deploy' ? input.deployment : {}, signal})
    const secret = typeof input.secret === 'string' ? input.secret : ''; if (secret && ['status', 'set', 'rotate', 'test'].includes(endpoint)) return call(`/v1/services/${encode(service)}/secrets/${encode(secret)}/${endpoint}`, {method: endpoint === 'status' ? 'POST' : 'POST', body: {value: input.value}, signal})
    return {ok: false as const, error: {code: 'internal' as const, message: 'unknown guarded operation', details: {}}}
  }, {authority: 'trusted-host'})
  ctx.tools.register(defineTool({name: 'dsh_docker_services', description: 'Read or operate only services allowlisted by the local DSH Docker controller. It cannot execute arbitrary Docker or shell commands.', parameters: {operation: {type: 'string', enum: ['inventory', 'health', 'logs', 'start', 'stop', 'restart', 'deploy', 'parameters', 'status', 'set', 'rotate', 'test'], required: true}, service: {type: 'string'}, secret: {type: 'string'}, tail: {type: 'integer'}, deployment: {type: 'object', additionalProperties: true}, values: {type: 'object', additionalProperties: true}, value: {type: 'string'}}, output: {schema: {type: 'json'}, render: (_arguments, value) => [{type: 'text', text: JSON.stringify(value)}]}, async execute(args) { const route = args.operation === 'inventory' ? '/v1/services' : args.operation === 'health' ? '/v1/health' : ''; if (route) return call(route); if (!args.service) throw new Error('service is required'); if (args.operation === 'logs') return call(`/v1/services/${encode(args.service)}/logs?tail=${Math.max(1, Math.min(1000, Number(args.tail) || 200))}`); if (['start', 'stop', 'restart'].includes(args.operation)) return call(`/v1/services/${encode(args.service)}/${args.operation}`, {method: 'POST'}); if (args.operation === 'deploy') return call(`/v1/services/${encode(args.service)}/deploy`, {method: 'POST', body: args.deployment}); if (args.operation === 'parameters') return call(`/v1/services/${encode(args.service)}/parameters`, {method: 'POST', body: {values: args.values}}); if (!args.secret) throw new Error('secret is required'); return call(`/v1/services/${encode(args.service)}/secrets/${encode(args.secret)}/${args.operation}`, {method: 'POST', body: {value: args.value}}) }}))
}
