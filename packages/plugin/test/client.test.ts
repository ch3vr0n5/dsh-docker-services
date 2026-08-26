import assert from 'node:assert/strict'
import test from 'node:test'
import { contained } from '../src/client.js'
test('controller failure is contained and redacted to a bounded plugin error', async () => { const result = await contained(Promise.reject(new Error('socket unavailable ' + 'x'.repeat(600)))); assert.equal(result.ok, false); if (!result.ok) { assert.equal(result.error.code, 'internal'); assert.equal(result.error.message.length, 512); assert.deepEqual(result.error.details, {}) } })
