import {execFileSync} from 'node:child_process'
import {mkdtemp, readdir, writeFile} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const root = process.cwd(); const artifacts = (await readdir(path.join(root, 'artifacts'))).filter(file => file.endsWith('.tgz')).map(file => path.join(root, 'artifacts', file)); if (artifacts.length !== 4) throw new Error('consumer test requires all four artifacts')
const dashboard = process.env.DSH_DASHBOARD_TARBALL
const consumer = await mkdtemp(path.join(os.tmpdir(), 'dsh-consumer-')); await writeFile(path.join(consumer, 'package.json'), JSON.stringify({name: 'clean-consumer', private: true, type: 'module'})); execFileSync('npm', ['install', '--ignore-scripts', ...(dashboard ? [] : ['--omit=peer']), '--no-audit', '--no-fund', ...artifacts, ...(dashboard ? [dashboard] : [])], {cwd: consumer, stdio: 'pipe'})
execFileSync(process.execPath, ['--input-type=module', '-e', "await import('dsh-docker-services/client'); await import('@dsh-docker-services/controller'); await import('@dsh-docker-services/proxy'); const c=await import('@dsh-docker-services/controller/package.json',{with:{type:'json'}}); const p=await import('@dsh-docker-services/proxy/package.json',{with:{type:'json'}}); if(c.default.bin['dsh-docker-services-controller']!=='./lib/src/main.js'||p.default.bin['dsh-docker-services-proxy']!=='./lib/src/main.js')throw new Error('bad bin')"], {cwd: consumer, stdio: 'pipe'})
const version = execFileSync(path.join(consumer, 'node_modules', '.bin', 'dsh-docker-services-controller'), ['--version'], {cwd: consumer, encoding: 'utf8'}).trim(); if (version !== '0.1.1') throw new Error(`controller bin failed: ${version}`)
console.log(`clean consumer imported plugin client, controller, and proxy from ${artifacts.length} packed artifacts${dashboard ? ' with Dashboard compatibility' : ''}`)
