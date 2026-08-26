import {execFileSync} from 'node:child_process'
execFileSync('docker', ['build', '--file', 'examples/container/Dockerfile', '--tag', 'dsh-docker-services:test', '.'], {stdio: 'inherit'})
const inspected = execFileSync('docker', ['image', 'inspect', 'dsh-docker-services:test', '--format', '{{.Config.User}} {{json .Config.Entrypoint}}'], {encoding: 'utf8'}).trim()
if (!inspected.startsWith('node ') || !inspected.includes('packages/controller/lib/src/main.js')) throw new Error(`unexpected image configuration: ${inspected}`)
const proxyVersion = execFileSync('docker', ['run', '--rm', '--entrypoint', 'node', 'dsh-docker-services:test', 'packages/proxy/lib/src/main.js', '--version'], {encoding: 'utf8'}).trim()
if (proxyVersion !== '0.1.1') throw new Error(`proxy is absent from the image: ${proxyVersion}`)
console.log(`verified container image and proxy: ${inspected}`)
