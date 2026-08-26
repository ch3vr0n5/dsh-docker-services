import {execFileSync} from 'node:child_process'
execFileSync('docker', ['build', '--file', 'examples/container/Dockerfile', '--tag', 'dsh-docker-services:test', '.'], {stdio: 'inherit'})
const inspected = execFileSync('docker', ['image', 'inspect', 'dsh-docker-services:test', '--format', '{{.Config.User}} {{json .Config.Entrypoint}}'], {encoding: 'utf8'}).trim()
if (!inspected.startsWith('node ') || !inspected.includes('packages/controller/lib/src/main.js')) throw new Error(`unexpected image configuration: ${inspected}`)
console.log(`verified container image: ${inspected}`)
