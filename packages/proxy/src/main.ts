#!/usr/bin/env node
import {readFile} from 'node:fs/promises'
import {parseProxyConfig, startProxy} from './proxy.js'

if (process.argv[2] === '--version') { console.log('0.1.1'); process.exit(0) }
const path = process.argv[2]
if (!path || !path.startsWith('/')) throw new Error('proxy config path must be absolute')
const config = parseProxyConfig(JSON.parse(await readFile(path, 'utf8')))
const proxy = await startProxy(config)
console.log(`dsh-docker-services proxy listening on ${config.socketPath}`)
for (const signal of ['SIGINT','SIGTERM']) process.on(signal, () => { void proxy.close().then(() => process.exit(0)) })
