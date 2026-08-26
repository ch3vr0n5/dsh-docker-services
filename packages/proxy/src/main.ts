#!/usr/bin/env node
import {chmod, readFile, rm} from 'node:fs/promises'
import {createProxy, parseProxyConfig} from './proxy.js'

if (process.argv[2] === '--version') { console.log('0.1.1'); process.exit(0) }
const path = process.argv[2]
if (!path || !path.startsWith('/')) throw new Error('proxy config path must be absolute')
const config = parseProxyConfig(JSON.parse(await readFile(path, 'utf8')))
const server = await createProxy(config)
await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(config.socketPath, resolve) })
await chmod(config.socketPath, config.socketMode ?? 0o600)
console.log(`dsh-docker-services proxy listening on ${config.socketPath}`)
for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => server.close(async () => { await rm(config.socketPath, {force:true}); process.exit(0) }))
