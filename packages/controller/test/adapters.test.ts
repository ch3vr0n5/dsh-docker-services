import assert from 'node:assert/strict'
import {chmod, mkdtemp, writeFile} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {RemoteDockerAdapter, runBounded, SshJsonTransport, TlsJsonTransport, type RemoteCall, type RemoteTransport} from '../src/docker.js'
import type {DeployResult, ServiceDefinition} from '@dsh-docker-services/shared'

test('bounded process execution rejects output floods, timeout, and cancellation', async () => {
  await assert.rejects(() => runBounded(process.execPath, ['-e', 'process.stdout.write("x".repeat(10000))'], {maxOutputBytes: 1024}), /exceeded bound/)
  await assert.rejects(() => runBounded(process.execPath, ['-e', 'setInterval(()=>{},1000)'], {timeoutMs: 100}), /timed out/)
  const abort = new AbortController(); const pending = runBounded(process.execPath, ['-e', 'setInterval(()=>{},1000)'], {timeoutMs: 10_000, signal: abort.signal}); abort.abort(); await assert.rejects(() => pending, /cancelled/)
  const preAborted = new AbortController(); preAborted.abort(); await assert.rejects(() => runBounded(process.execPath, ['-e', 'setInterval(()=>{},1000)'], {signal: preAborted.signal}), /cancelled/)
})
test('SSH transport bounds remote output and uses only its fixed helper target', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'dsh-ssh-')); const script = path.join(root, 'fake-ssh'); await writeFile(script, '#!/bin/sh\nprintf \'%010000d\' 1\n', {mode: 0o700}); await chmod(script, 0o700); const transport = new SshJsonTransport({binary: script, host: 'remote.example', user: 'controller', knownHosts: path.join(root, 'known-hosts'), helper: '/usr/local/libexec/dsh-remote', timeoutMs: 1000, maxOutputBytes: 1024}); await assert.rejects(() => transport.call({operation: 'inventory'}), /exceeded bound/)
})
test('TLS transport rejects non-HTTPS or mutable endpoint forms before I/O', async () => { const transport = new TlsJsonTransport({url: 'http://example.invalid/controller', caFile: '/no/ca', certFile: '/no/cert', keyFile: '/no/key'}); await assert.rejects(() => transport.call({operation: 'inventory'}), /invalid fixed TLS endpoint/) })
test('remote deploy rejects failed tests and verifies the actual running digest', async () => { const request = {repo: 'https://example.invalid/repo.git', branch: 'release', sha: 'a'.repeat(40), idempotencyKey: 'deploy-request-0001'}; const service = {name: 'api', containers: ['api'], actions: ['deploy']} as ServiceDefinition; let digest = `sha256:${'b'.repeat(64)}`; let result: DeployResult = {repo: request.repo, branch: request.branch, sha: request.sha, imageDigest: digest, deployedAt: new Date().toISOString(), testState: 'passed', reachable: true, branchVerified: true}; const transport: RemoteTransport = {async call(call: RemoteCall) { if (call.operation === 'deploy') return result; return [{name: 'api', image: `repo@${digest}`, imageDigest: digest, status: 'running', health: 'healthy', startedAt: null, resources: {cpuPercent: null, memoryBytes: null}, controlled: false}] }}; const adapter = new RemoteDockerAdapter(transport); assert.equal((await adapter.deploy(service, request)).imageDigest, digest); result = {...result, testState: 'failed'}; await assert.rejects(() => adapter.deploy(service, request), /untrusted or incomplete/); result = {...result, testState: 'passed'}; digest = `sha256:${'c'.repeat(64)}`; await assert.rejects(() => adapter.deploy(service, request), /do not run the reported digest/) })
