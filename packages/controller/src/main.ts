#!/usr/bin/env node
import {lstat, unlink} from 'node:fs/promises'
import path from 'node:path'
import {assertConfig, type ControllerConfig} from '@dsh-docker-services/shared'
import {Controller} from './controller.js'
import {assertDockerSocket, assertTrustedExecutable, LocalDockerAdapter, RemoteDockerAdapter, SshJsonTransport, TlsJsonTransport} from './docker.js'
import {createServer, HmacProxyAuthenticator} from './server.js'
import {ensureOwnedRoot, ProtectedLogger, readProtectedFile} from './security.js'

if (process.argv[2] === '--version') { console.log('0.1.1'); process.exit(0) }
const configPath = process.argv[2] ?? '/etc/dsh-docker-services/controller.json'
const config = JSON.parse((await readProtectedFile(configPath, 1024 * 1024)).toString('utf8')) as ControllerConfig; assertConfig(config)
await ensureOwnedRoot(path.dirname(config.socketPath)); await ensureOwnedRoot(path.join(config.stateDir, 'logs')); await assertTrustedExecutable(config.docker.binary)
if (config.docker.kind === 'local') await assertDockerSocket(config.docker.host)
if (config.docker.kind === 'ssh') { await assertTrustedExecutable(config.docker.ssh!.binary); await readProtectedFile(config.docker.ssh!.knownHosts, 1024 * 1024); if (config.docker.ssh!.identityFile) await readProtectedFile(config.docker.ssh!.identityFile, 64 * 1024) }
try { const info = await lstat(config.socketPath); if (!info.isSocket() || info.isSymbolicLink() || (typeof process.getuid === 'function' && info.uid !== process.getuid())) throw new Error('refusing to replace unsafe controller socket'); await unlink(config.socketPath) } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
const docker = config.docker.kind === 'local' ? new LocalDockerAdapter(config.docker) : config.docker.kind === 'ssh' ? new RemoteDockerAdapter(new SshJsonTransport(config.docker.ssh!)) : new RemoteDockerAdapter(new TlsJsonTransport(config.docker.tls!))
const controller = await Controller.create(config, docker); const authenticator = await HmacProxyAuthenticator.create(config.auth, config.roles, path.join(config.stateDir, 'auth-replay')); const logger = new ProtectedLogger(path.join(config.stateDir, 'logs', 'controller-errors.jsonl')); const server = createServer(controller, authenticator, logger)
const socketMode=config.socketMode??0o600;server.once('listening',async()=>{const info=await lstat(config.socketPath);if(!info.isSocket()||(typeof process.getuid==='function'&&info.uid!==process.getuid())||(info.mode&0o777)!==socketMode){server.closeAllConnections();throw new Error('controller socket was not bound with the required mode')}console.log(`dsh-docker-services controller listening on ${config.socketPath}`)})
const previousUmask=process.umask(0o777&~socketMode);try{server.listen(config.socketPath)}finally{process.umask(previousUmask)}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)))
