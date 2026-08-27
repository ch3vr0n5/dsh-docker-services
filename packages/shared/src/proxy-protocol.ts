import {createHash, createHmac, timingSafeEqual} from 'node:crypto'

/**
 * Byte-level protocol for the private proxy/controller lane.  This deliberately
 * does not use JSON: every field is length framed in a fixed order, so key order,
 * whitespace, and Unicode rendering cannot affect what is authenticated.
 */
export const proxyProtocolVersion = 1 as const
export const requestHeaderNames = ['content-type', 'content-length'] as const
export const responseHeaderNames = ['content-type', 'content-length', 'cache-control', 'x-content-type-options', 'x-request-id'] as const
export type SelectedHeaders = Record<string, string | null>
export type RequestBinding = { protocolVersion: 1; requestId: string; nonce: string; actor: string; role: string; method: string; target: string; headers: SelectedHeaders; bodyDigest: string; bodyLength: number }
export type ResponseBinding = { protocolVersion: 1; requestId: string; nonce: string; requestDigest: string; status: number; headers: SelectedHeaders; bodyDigest: string; bodyLength: number; outcome: 'ok' | 'error' }

const base64url = /^[A-Za-z0-9_-]{16,128}$/
const identifier = /^[a-z][a-z0-9-]{0,62}$/
const digest = /^[0-9a-f]{64}$/
const ascii = /^[\x20-\x7e]*$/
const decimal = /^(?:0|[1-9][0-9]{0,8})$/

function u32(value: number): Buffer { if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) throw new Error('protocol field length rejected'); const result = Buffer.allocUnsafe(4); result.writeUInt32BE(value); return result }
function frame(name: string, value: Buffer): Buffer { const label = Buffer.from(name, 'ascii'); if (label.toString('ascii') !== name || !/^[a-z0-9-]+$/.test(name)) throw new Error('protocol field name rejected'); return Buffer.concat([u32(label.length), label, u32(value.length), value]) }
function text(value: string, label: string): Buffer { if (!ascii.test(value)) throw new Error(`${label} must be printable ASCII`); return Buffer.from(value, 'ascii') }
function headers(value: SelectedHeaders, names: readonly string[]): Buffer {
  if (Object.keys(value).some(name => !names.includes(name))) throw new Error('protocol selected headers rejected')
  const parts: Buffer[] = []
  for (const name of names) {
    const item = value[name]
    if (item !== null && item !== undefined && (!ascii.test(item) || /[\r\n\0]/.test(item))) throw new Error('protocol header value rejected')
    const present = item === null || item === undefined ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), text(item, 'header value')])
    parts.push(frame(`header-${name}`, present))
  }
  return Buffer.concat(parts)
}
function canonical(domain: string, fields: Array<readonly [string, Buffer]>): Buffer {
  const prefix = Buffer.from(`dsh-docker-services/${domain}/v1\n`, 'ascii')
  return Buffer.concat([prefix, ...fields.map(([name, value]) => frame(name, value))])
}

export function normalizeMethod(value: string): string { if (value !== 'GET' && value !== 'POST') throw new Error('protocol method rejected'); return value }
export function normalizeTarget(value: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.length > 8192 || /[\0\r\n#\\]/.test(value)) throw new Error('protocol target rejected')
  const parsed = new URL(value, 'http://controller.invalid')
  if (parsed.origin !== 'http://controller.invalid' || !parsed.pathname.startsWith('/')) throw new Error('protocol target rejected')
  const result = `${parsed.pathname}${parsed.search}`
  if (!ascii.test(result)) throw new Error('protocol target rejected')
  return result
}
export function sha256Hex(value: Buffer): string { return createHash('sha256').update(value).digest('hex') }
export function requestCanonical(value: RequestBinding): Buffer {
  if (value.protocolVersion !== proxyProtocolVersion || !base64url.test(value.requestId) || !base64url.test(value.nonce) || !identifier.test(value.actor) || !identifier.test(value.role) || !digest.test(value.bodyDigest) || !Number.isSafeInteger(value.bodyLength) || value.bodyLength < 0) throw new Error('request binding rejected')
  const method = normalizeMethod(value.method); const target = normalizeTarget(value.target)
  return canonical('proxy-request', [['protocol-version', text(String(value.protocolVersion), 'protocol version')], ['request-id', text(value.requestId, 'request id')], ['nonce', text(value.nonce, 'nonce')], ['actor', text(value.actor, 'actor')], ['role', text(value.role, 'role')], ['method', text(method, 'method')], ['target', text(target, 'target')], ['selected-headers', headers(value.headers, requestHeaderNames)], ['body-digest', text(value.bodyDigest, 'body digest')], ['body-length', text(String(value.bodyLength), 'body length')]])
}
export function responseCanonical(value: ResponseBinding): Buffer {
  if (value.protocolVersion !== proxyProtocolVersion || !base64url.test(value.requestId) || !base64url.test(value.nonce) || !digest.test(value.requestDigest) || !digest.test(value.bodyDigest) || !Number.isSafeInteger(value.status) || value.status < 100 || value.status > 599 || !Number.isSafeInteger(value.bodyLength) || value.bodyLength < 0 || (value.outcome !== 'ok' && value.outcome !== 'error')) throw new Error('response binding rejected')
  if ((value.status >= 200 && value.status < 300) !== (value.outcome === 'ok')) throw new Error('response outcome rejected')
  return canonical('controller-response', [['protocol-version', text(String(value.protocolVersion), 'protocol version')], ['request-id', text(value.requestId, 'request id')], ['nonce', text(value.nonce, 'nonce')], ['request-digest', text(value.requestDigest, 'request digest')], ['status', text(String(value.status), 'status')], ['selected-headers', headers(value.headers, responseHeaderNames)], ['body-digest', text(value.bodyDigest, 'body digest')], ['body-length', text(String(value.bodyLength), 'body length')], ['outcome', text(value.outcome, 'outcome')]])
}
export function selectedHeaders(input: Record<string, string | string[] | undefined>, names: readonly string[]): SelectedHeaders {
  const result: SelectedHeaders = {}
  for (const name of names) {
    const value = input[name]
    if (Array.isArray(value)) throw new Error('duplicate protocol header rejected')
    if (value === undefined) result[name] = null
    else if (!ascii.test(value) || /[\r\n\0]/.test(value)) throw new Error('protocol header value rejected')
    else result[name] = value
  }
  return result
}
export function requiredDecimalHeader(value: string | null, length: number): void { if (value === null || !decimal.test(value) || Number(value) !== length) throw new Error('protocol content length rejected') }
function derivedKey(key: Buffer, purpose: 'assertion' | 'handshake' | 'request' | 'response'): Buffer { return createHmac('sha256', key).update(`dsh-docker-services/key-derivation/v1\n${purpose}\n`, 'ascii').digest() }
export function signMac(key: Buffer, purpose: 'assertion' | 'handshake' | 'request' | 'response', value: Buffer): string { return createHmac('sha256', derivedKey(key, purpose)).update(value).digest('base64url') }
export function verifyMac(key: Buffer, purpose: 'assertion' | 'handshake' | 'request' | 'response', value: Buffer, encoded: string): boolean {
  if (!base64url.test(encoded)) return false
  let actual: Buffer; try { actual = Buffer.from(encoded, 'base64url') } catch { return false }
  const expected = Buffer.from(signMac(key, purpose, value), 'base64url')
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}
