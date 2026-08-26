import {execFileSync} from 'node:child_process'
import {readdir, stat} from 'node:fs/promises'

const files = (await readdir('artifacts')).filter(file => file.endsWith('.tgz')); if (files.length !== 3) throw new Error(`expected three artifacts, found ${files.length}`)
const expected = new Map([
  ['dsh-docker-services', ['lib/src/index.js', 'lib/src/client.js']],
  ['@dsh-docker-services/controller', ['lib/src/index.js', 'lib/src/main.js']],
  ['@dsh-docker-services/shared', ['lib/index.js']],
])
for (const file of files) {
  const artifact = `artifacts/${file}`; if ((await stat(artifact)).size < 2048) throw new Error(`${artifact} is unexpectedly small`); const entries = execFileSync('tar', ['-tzf', artifact], {encoding: 'utf8'}).trim().split('\n').map(entry => entry.replace(/^package\//, '')); const packageJson = JSON.parse(execFileSync('tar', ['-xOzf', artifact, 'package/package.json'], {encoding: 'utf8'})); const required = expected.get(packageJson.name); if (!required) throw new Error(`unexpected artifact package ${packageJson.name}`); for (const entry of required) if (!entries.includes(entry)) throw new Error(`${packageJson.name} lacks ${entry}`); if (entries.some(entry => /(^|\/)(\.env|node_modules|test|state)(\/|$)/.test(entry))) throw new Error(`${packageJson.name} contains prohibited content`); const license = execFileSync('tar', ['-xOzf', artifact, 'package/LICENSE'], {encoding: 'utf8'}); if (!license.includes('Apache License') || !license.includes('TERMS AND CONDITIONS') || license.length < 8000) throw new Error(`${packageJson.name} lacks the full Apache-2.0 license`); if (packageJson.name === '@dsh-docker-services/controller' && packageJson.bin?.['dsh-docker-services-controller'] !== './lib/src/main.js') throw new Error('controller bin target is invalid')
  console.log(`verified ${artifact}`)
}
