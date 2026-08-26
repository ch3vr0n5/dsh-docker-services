import http from 'node:http'
export type RequestOptions = {method?: string; body?: unknown; signal?: AbortSignal}
export type ControllerTransport = {request<T>(route: string, options?: RequestOptions): Promise<T>}
export class UnixSocketTransport implements ControllerTransport {
  constructor(private readonly socketPath: string, private readonly timeoutMs = 15_000, private readonly maxOutputBytes = 1024 * 1024) {}
  request<T>(route: string, options: RequestOptions = {}): Promise<T> {
    return new Promise((resolve, reject) => {
      const payload = options.body === undefined ? undefined : JSON.stringify(options.body); if (payload && Buffer.byteLength(payload) > 64 * 1024) return reject(new Error('controller request exceeds bound'))
      let settled = false; const finish = (error?: Error, value?: T) => { if (settled) return; settled = true; clearTimeout(timer); options.signal?.removeEventListener('abort', abort); error ? reject(error) : resolve(value as T) }
      const req = http.request({socketPath: this.socketPath, path: route, method: options.method ?? 'GET', headers: payload ? {'content-type': 'application/json', 'content-length': Buffer.byteLength(payload)} : {}}, response => { const chunks: Buffer[] = []; let bytes = 0; response.on('data', chunk => { bytes += chunk.length; if (bytes > this.maxOutputBytes) { req.destroy(); finish(new Error('controller response exceeds bound')) } else chunks.push(Buffer.from(chunk)) }); response.on('end', () => { try { const value = JSON.parse(Buffer.concat(chunks).toString('utf8')); if ((response.statusCode ?? 500) >= 400) finish(new Error('controller rejected request')); else finish(undefined, value as T) } catch { finish(new Error('controller returned invalid JSON')) } }) })
      const abort = () => { req.destroy(); finish(new Error('controller request cancelled')) }; options.signal?.addEventListener('abort', abort, {once: true}); const timer = setTimeout(() => { req.destroy(); finish(new Error('controller request timed out')) }, Math.max(100, Math.min(60_000, this.timeoutMs))); timer.unref(); if (options.signal?.aborted) abort(); req.on('error', () => finish(new Error('controller unavailable'))); if (payload) req.end(payload); else req.end()
    })
  }
}
/** Converts failures to a bounded generic RPC error so the privileged dependency cannot crash or leak into DSH. */
export async function contained<T>(request: Promise<T>): Promise<{ok: true; value: T} | {ok: false; error: {code: 'internal'; message: string; details: {}}}> { try { return {ok: true, value: await request} } catch { return {ok: false, error: {code: 'internal', message: 'Docker services controller unavailable or request rejected', details: {}}} } }
