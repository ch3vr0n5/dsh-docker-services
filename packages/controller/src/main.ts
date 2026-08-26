import { readFile, mkdir, rm, chmod } from 'node:fs/promises'
import path from 'node:path'
import { assertConfig, type ControllerConfig } from '@dsh-docker-services/shared'
import { Controller } from './controller.js'
import { LocalDockerAdapter, RemoteDockerAdapter, SshJsonTransport, TlsJsonTransport } from './docker.js'
import { createServer } from './server.js'
const configPath = process.env.DSH_DOCKER_SERVICES_CONFIG ?? '/etc/dsh-docker-services/controller.json'; const socketPath = process.env.DSH_DOCKER_SERVICES_SOCKET ?? '/run/dsh-docker-services/controller.sock'
const config = JSON.parse(await readFile(configPath, 'utf8')) as ControllerConfig; assertConfig(config)
const docker = config.docker.kind === 'local' ? new LocalDockerAdapter() : config.docker.kind === 'ssh' ? new RemoteDockerAdapter(new SshJsonTransport(config.docker.ssh!)) : new RemoteDockerAdapter(new TlsJsonTransport(config.docker.tls!))
await mkdir(path.dirname(socketPath), {recursive: true}); await rm(socketPath, {force: true}); const server = createServer(new Controller(config, docker)); server.listen(socketPath, async () => { await chmod(socketPath, 0o660); console.log(`dsh-docker-services controller listening on ${socketPath}`) }); for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)))
