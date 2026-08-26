import assert from 'node:assert/strict'
import {mkdtemp} from 'node:fs/promises'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {contained, UnixSocketTransport} from '../src/client.js'

test('controller failures are generic and do not leak protected details', async () => { const secret = 'password=must-not-leak'; const result = await contained(Promise.reject(new Error(secret))); assert.equal(result.ok, false); assert.equal(JSON.stringify(result).includes(secret), false); if (!result.ok) assert.equal(result.error.message, 'Docker services controller unavailable or request rejected') })
test('Unix client bounds output and timeout', async t => { const root = await mkdtemp(path.join(os.tmpdir(), 'dsh-client-')); const socket = path.join(root, 'server.sock'); const server = http.createServer((req, res) => { if (req.url === '/large') res.end(JSON.stringify({value: 'x'.repeat(10_000)})); else if (req.url === '/slow') return; else res.end('{}') }); await new Promise<void>(resolve => server.listen(socket, resolve)); t.after(() => new Promise<void>(resolve => server.close(() => resolve()))); const client = new UnixSocketTransport(socket, 100, 1024); await assert.rejects(() => client.request('/large'), /exceeds bound/); await assert.rejects(() => client.request('/slow'), /timed out/) })
test('Unix client propagates cancellation', async t => { const root = await mkdtemp(path.join(os.tmpdir(), 'dsh-client-')); const socket = path.join(root, 'server.sock'); const server = http.createServer(() => undefined); await new Promise<void>(resolve => server.listen(socket, resolve)); t.after(() => new Promise<void>(resolve => server.close(() => resolve()))); const abort = new AbortController(); const pending = new UnixSocketTransport(socket, 10_000).request('/cancel', {signal: abort.signal}); abort.abort(); await assert.rejects(() => pending, /cancelled/) })
