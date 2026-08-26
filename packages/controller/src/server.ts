import http, {type IncomingHttpHeaders, type IncomingMessage, type ServerResponse} from 'node:http'
import type {Controller, Identity} from './controller.js'
import {HmacProxyAuthenticator, ProtectedLogger, publicMessage, requestId, SafeError} from './security.js'

export interface RequestAuthenticator { authenticate(headers: IncomingHttpHeaders): Promise<Identity> | Identity; proveController?(challenge: string): Promise<string> | string }
async function body(req: IncomingMessage): Promise<unknown> { const chunks: Buffer[] = []; let bytes = 0; for await (const chunk of req) { bytes += chunk.length; if (bytes > 64 * 1024) throw new SafeError('bad_request', 413, 'request body too large'); chunks.push(Buffer.from(chunk)) } if (!chunks.length) return {}; try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { throw new SafeError('bad_request', 400, 'invalid JSON body') } }
function send(res: ServerResponse, status: number, value: unknown, id: string): void { const payload = JSON.stringify(value); res.writeHead(status, {'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': id}); res.end(payload) }
export function createServer(controller: Controller, authenticator: RequestAuthenticator, logger: ProtectedLogger): http.Server {
  return http.createServer(async (req, res) => {
    const id = requestId(); const abort = new AbortController(); req.once('aborted', () => abort.abort()); res.once('close', () => { if (!res.writableEnded) abort.abort() })
    try {
      const identity = await authenticator.authenticate(req.headers); const url = new URL(req.url ?? '/', 'http://localhost')
      if (req.method === 'GET' && url.pathname === '/v1/proxy-handshake') {
        const challenge = req.headers['x-dsh-proxy-challenge']
        if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(challenge) || !authenticator.proveController) throw new SafeError('unauthorized', 401, 'controller authentication challenge rejected')
        const proof = await authenticator.proveController(challenge)
        const payload = JSON.stringify({protocolVersion: 1, challenge, proof}); res.writeHead(200, {'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff'}); res.end(payload); return
      }
      if (req.method === 'GET' && url.pathname === '/v1/health') return send(res, 200, await controller.health(identity), id)
      if (req.method === 'GET' && url.pathname === '/v1/services') return send(res, 200, await controller.inventory(identity, abort.signal), id)
      if (req.method === 'GET' && url.pathname === '/v1/audit') return send(res, 200, await controller.auditEntries(identity, Number(url.searchParams.get('limit') ?? '100')), id)
      const match = url.pathname.match(/^\/v1\/services\/([a-z0-9-]+)(?:\/(.+))?$/); if (!match) throw new SafeError('not_found', 404, 'route not found'); const service = match[1]!; const action = match[2] ?? ''
      if (req.method === 'GET' && action === 'logs') return send(res, 200, await controller.logs(identity, service, Number(url.searchParams.get('tail') ?? '200'), abort.signal), id)
      if (req.method !== 'POST') throw new SafeError('not_found', 404, 'route not found'); const payload = await body(req) as Record<string, unknown>
      if (['start', 'stop', 'restart'].includes(action)) return send(res, 200, await controller.action(identity, service, action as 'start' | 'stop' | 'restart', abort.signal), id)
      if (action === 'deploy') return send(res, 200, await controller.deploy(identity, service, payload, abort.signal), id)
      if (action === 'parameters') return send(res, 200, await controller.parameters(identity, service, payload.values), id)
      const secret = action.match(/^secrets\/([a-z0-9-]+)\/(status|set|rotate|test)$/); if (secret) return send(res, 200, await controller.secret(identity, service, secret[1]!, secret[2] as 'status' | 'set' | 'rotate' | 'test', payload.value, abort.signal), id)
      throw new SafeError('not_found', 404, 'route not found')
    } catch (error) {
      await logger.log(id, error).catch(() => undefined); const safe = error instanceof SafeError ? error : new SafeError('internal', 500, 'unexpected controller failure'); if (!res.headersSent) send(res, safe.status, {error: {code: safe.code, message: publicMessage(safe), requestId: id}}, id)
    }
  })
}
export {HmacProxyAuthenticator}
