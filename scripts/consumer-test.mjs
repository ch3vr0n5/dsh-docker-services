import {execFileSync} from 'node:child_process'
import {mkdtemp, readdir, writeFile} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const root = process.cwd(); const artifacts = (await readdir(path.join(root, 'artifacts'))).filter(file => file.endsWith('.tgz')).map(file => path.join(root, 'artifacts', file)); if (artifacts.length !== 3) throw new Error('consumer test requires all three artifacts')
const consumer = await mkdtemp(path.join(os.tmpdir(), 'dsh-consumer-')); await writeFile(path.join(consumer, 'package.json'), JSON.stringify({name: 'clean-consumer', private: true, type: 'module'})); execFileSync('npm', ['install', '--ignore-scripts', '--omit=peer', '--no-audit', '--no-fund', ...artifacts], {cwd: consumer, stdio: 'pipe'})
execFileSync(process.execPath, ['--input-type=module', '-e', "await import('dsh-docker-services/client'); await import('@dsh-docker-services/controller'); const p=await import('@dsh-docker-services/controller/package.json',{with:{type:'json'}}); if(p.default.bin['dsh-docker-services-controller']!=='./lib/src/main.js')throw new Error('bad controller bin')"], {cwd: consumer, stdio: 'pipe'})
const version = execFileSync(path.join(consumer, 'node_modules', '.bin', 'dsh-docker-services-controller'), ['--version'], {cwd: consumer, encoding: 'utf8'}).trim(); if (version !== '0.1.0') throw new Error(`controller bin failed: ${version}`)
console.log(`clean consumer imported plugin client and controller from ${artifacts.length} packed artifacts`)
