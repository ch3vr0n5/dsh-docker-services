import {createHash} from 'node:crypto'
import {execFileSync} from 'node:child_process'
import {readFile} from 'node:fs/promises'
import path from 'node:path'

const expected = {
  sourceCommit: '091f351c219c2d5acd775b6f09ccb036c125cf77',
  packageName: 'dsh-dashboard',
  version: '0.8.9',
  sha256: '524527b8139967c0967aaa86be1fbecd2fc6a151f6ffeb681f5510aeee86129b',
}
const tarball = process.env.DSH_DASHBOARD_TARBALL
if (!tarball) throw new Error('DSH_DASHBOARD_TARBALL must point to the pinned Dashboard 0.8.9 artifact')
const artifact = path.resolve(tarball)
const digest = createHash('sha256').update(await readFile(artifact)).digest('hex')
if (digest !== expected.sha256) throw new Error(`Dashboard artifact digest mismatch: expected ${expected.sha256}, received ${digest}`)
const manifest = JSON.parse(execFileSync('tar', ['-xOf', artifact, 'package/package.json'], {encoding: 'utf8'}))
if (manifest.name !== expected.packageName || manifest.version !== expected.version) throw new Error('Dashboard artifact has an unexpected package identity')
execFileSync('npm', ['run', 'test:consumer'], {cwd: process.cwd(), env: {...process.env, DSH_DASHBOARD_TARBALL: artifact}, stdio: 'inherit'})
console.log(`Dashboard compatibility verified: ${manifest.name}@${manifest.version}, source ${expected.sourceCommit}, sha256 ${digest}`)
