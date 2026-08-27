import http, {type IncomingHttpHeaders, type IncomingMessage, type ServerResponse} from 'node:http'
import {proxyProtocolVersion, responseHeaderNames} from '@dsh-docker-services/shared'
import type {Controller, Identity} from './controller.js'
import {HmacProxyAuthenticator, ProtectedLogger, publicMessage, requestId, SafeError, type AuthenticatedRequest} from './security.js'

export interface RequestAuthenticator {
  authenticate(headers: IncomingHttpHeaders): Promise<Identity> | Identity
  authenticateRequest(headers: IncomingHttpHeaders, method: string, target: string, rawBody: Buffer): Promise<AuthenticatedRequest>
  signResponse(request: AuthenticatedRequest, status: number, headers: Record<string, string | undefined>, payload: Buffer): {binding: {outcome: 'ok' | 'error'}; mac: string}
  proveController?(challenge: string): Promise<string> | string
}

async function rawBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []; let bytes = 0
  for await (const chunk of req) { bytes += chunk.length; if (bytes > 64 * 1024) throw new SafeError('bad_request', 413, 'request body too large'); chunks.push(Buffer.from(chunk)) }
  return Buffer.concat(chunks)
}
function parsedBody(raw: Buffer): Record<string, unknown> { if (!raw.length) return {}; try { const value: unknown = JSON.parse(raw.toString('utf8')); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not object'); return value as Record<string, unknown> } catch { throw new SafeError('bad_request', 400, 'invalid JSON body') } }
function exactlyOneHeader(req: IncomingMessage, name: string, required = false): void {
  let count = 0
  for (let index = 0; index < req.rawHeaders.length; index += 2) if (req.rawHeaders[index]?.toLowerCase() === name) count += 1
  if (count > 1 || (required && count !== 1)) throw new SafeError('unauthorized', 401, 'duplicate or missing proxy header')
}
function checkProtocolHeaders(req: IncomingMessage): void {
  for (const name of ['x-dsh-proxy-assertion', 'x-dsh-protocol-version', 'x-dsh-request-id', 'x-dsh-request-nonce', 'x-dsh-request-mac', 'content-length', 'content-type']) exactlyOneHeader(req, name, name !== 'content-type')
}
function send(res: ServerResponse, status: number, value: unknown, id: string, authenticator: RequestAuthenticator, request: AuthenticatedRequest): void {
  const payload = Buffer.from(JSON.stringify(value), 'utf8')
  const headers: Record<string, string | undefined> = {'content-type': 'application/json', 'content-length': String(payload.length), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': id}
  const signed = authenticator.signResponse(request, status, headers, payload)
  const responseHeaders: Record<string, string> = {}
  for (const name of responseHeaderNames) { const value = headers[name]; if (value !== undefined) responseHeaders[name] = value }
  responseHeaders['x-dsh-protocol-version'] = String(proxyProtocolVersion)
  responseHeaders['x-dsh-request-id'] = request.binding.requestId
  responseHeaders['x-dsh-request-nonce'] = request.binding.nonce
  responseHeaders['x-dsh-request-digest'] = request.digest
  responseHeaders['x-dsh-response-outcome'] = signed.binding.outcome
  responseHeaders['x-dsh-response-mac'] = signed.mac
  res.writeHead(status, responseHeaders); res.end(payload)
}

export function createServer(controller: Controller, authenticator: RequestAuthenticator, logger: ProtectedLogger): http.Server {
  return http.createServer(async (req, res) => {
    const id = requestId(); const abort = new AbortController(); let request: AuthenticatedRequest | undefined
    req.once('aborted', () => abort.abort()); res.once('close', () => { if (!res.writableEnded) abort.abort() })
    try {
      const url = new URL(req.url ?? '/', 'http://localhost')
      if (req.method === 'GET' && url.pathname === '/v1/proxy-handshake') {
        const identity = await authenticator.authenticate(req.headers)
        if (!identity) throw new SafeError('unauthorized', 401, 'controller authentication rejected')
        const challenge = req.headers['x-dsh-proxy-challenge']
        if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(challenge) || !authenticator.proveController) throw new SafeError('unauthorized', 401, 'controller authentication challenge rejected')
        const proof = await authenticator.proveController(challenge)
        const payload = JSON.stringify({protocolVersion: 1, challenge, proof}); res.writeHead(200, {'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff'}); res.end(payload); return
      }
      checkProtocolHeaders(req)
      const raw = await rawBody(req)
      request = await authenticator.authenticateRequest(req.headers, req.method ?? '', req.url ?? '/', raw)
      const identity = request.identity
      if (req.method === 'GET' && url.pathname === '/v1/health') return send(res, 200, await controller.health(identity), id, authenticator, request)
      if (req.method === 'GET' && url.pathname === '/v1/services') return send(res, 200, await controller.inventory(identity, abort.signal), id, authenticator, request)
      if (req.method === 'GET' && url.pathname === '/v1/audit') return send(res, 200, await controller.auditEntries(identity, Number(url.searchParams.get('limit') ?? '100')), id, authenticator, request)
      const match = url.pathname.match(/^\/v1\/services\/([a-z0-9-]+)(?:\/(.+))?$/); if (!match) throw new SafeError('not_found', 404, 'route not found'); const service = match[1]!; const action = match[2] ?? ''
      if (req.method === 'GET' && action === 'logs') return send(res, 200, await controller.logs(identity, service, Number(url.searchParams.get('tail') ?? '200')), id, authenticator, request)
      if (req.method !== 'POST') throw new SafeError('not_found', 404, 'route not found'); const payload = parsedBody(raw)
      if (['start', 'stop', 'restart'].includes(action)) return send(res, 200, await controller.action(identity, service, action as 'start' | 'stop' | 'restart', abort.signal), id, authenticator, request)
      if (action === 'deploy') return send(res, 200, await controller.deploy(identity, service, payload, abort.signal), id, authenticator, request)
      if (action === 'parameters') return send(res, 200, await controller.parameters(identity, service, payload.values), id, authenticator, request)
      const secret = action.match(/^secrets\/([a-z0-9-]+)\/(status|set|rotate|test)$/); if (secret) return send(res, 200, await controller.secret(identity, service, secret[1]!, secret[2] as 'status' | 'set' | 'rotate' | 'test', payload.value, abort.signal), id, authenticator, request)
      throw new SafeError('not_found', 404, 'route not found')
    } catch (error) {
      await logger.log(id, error).catch(() => undefined)
      const safe = error instanceof SafeError ? error : new SafeError('internal', 500, 'unexpected controller failure')
      if (!res.headersSent && request) send(res, safe.status, {error: {code: safe.code, message: publicMessage(safe), requestId: id}}, id, authenticator, request)
      else if (!res.headersSent) { const payload = JSON.stringify({error: {code: 'unavailable', message: 'controller authentication failed', requestId: id}}); res.writeHead(401, {'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), 'cache-control': 'no-store'}); res.end(payload) }
    }
  })
}
export {HmacProxyAuthenticator}
