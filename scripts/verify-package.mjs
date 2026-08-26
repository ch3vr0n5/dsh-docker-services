import { readdir, readFile, stat } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
const files = (await readdir('artifacts')).filter(file => file.endsWith('.tgz'))
if (files.length !== 1) throw new Error(`expected one plugin artifact, found ${files.length}`)
const artifact = `artifacts/${files[0]}`
if ((await stat(artifact)).size < 1024) throw new Error('plugin artifact is unexpectedly small')
const entries = execFileSync('tar', ['-tzf', artifact], {encoding: 'utf8'}).split('\n')
if (!entries.some(entry => entry === 'package/lib/src/index.js')) throw new Error('artifact lacks compiled plugin entrypoint')
if (entries.some(entry => /(^|\/)(\.env|node_modules|test|state)(\/|$)/.test(entry))) throw new Error('artifact includes prohibited content')
const packageJson = JSON.parse(execFileSync('tar', ['-xOzf', artifact, 'package/package.json'], {encoding: 'utf8'}))
if (packageJson.name !== 'dsh-docker-services') throw new Error('wrong artifact package name')
console.log(`verified ${artifact}`)
