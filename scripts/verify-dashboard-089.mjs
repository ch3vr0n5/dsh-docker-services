import {createHash} from 'node:crypto'
import {execFileSync} from 'node:child_process'
import {mkdtemp, readFile, readdir, rm} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const root=process.cwd()
const admitted={repository:'https://github.com/ch3vr0n5/dsh-dashboard.git',commit:'091f351c219c2d5acd775b6f09ccb036c125cf77',name:'dsh-dashboard',version:'0.8.9',pnpm:'11.19.0',files:{'package.json':'48298381ca568c53f38cd5eafa43f089a6470e978d8e3a612babe1d861ecd6b8','pnpm-lock.yaml':'d850f6b0558020a53591300be528fae51d7f19ca3f815a22b61223f7084e7a2d','pnpm-workspace.yaml':'7be9e4597f2eca13fe33abfb8691354aa41bb5e698fe4171a45ae265137099d6'}}
const run=(file,args,cwd,options={})=>execFileSync(file,args,{cwd,stdio:'pipe',encoding:'utf8',...options})
const digest=async file=>createHash('sha256').update(await readFile(file)).digest('hex')
const temporary=await mkdtemp(path.join(os.tmpdir(),'dsh-dashboard-089-gate-'));const checkout=path.join(temporary,'source');const output=path.join(temporary,'artifact')
run('git',['init',checkout],root);run('git',['remote','add','origin',admitted.repository],checkout);run('git',['fetch','--depth','1','origin',admitted.commit],checkout);run('git',['checkout','--detach','FETCH_HEAD'],checkout)
if(run('git',['rev-parse','HEAD'],checkout).trim()!==admitted.commit)throw new Error('Dashboard source commit mismatch')
for(const [file,expected] of Object.entries(admitted.files)){const actual=await digest(path.join(checkout,file));if(actual!==expected)throw new Error(`Dashboard ${file} digest mismatch`)}
const manifest=JSON.parse(await readFile(path.join(checkout,'package.json'),'utf8'));if(manifest.name!==admitted.name||manifest.version!==admitted.version||manifest.packageManager!==`pnpm@${admitted.pnpm}`)throw new Error('Dashboard package or package-manager identity mismatch')
const pnpm=path.join(root,'node_modules','.bin','pnpm');if(run(pnpm,['--version'],checkout).trim()!==admitted.pnpm)throw new Error('pinned pnpm toolchain mismatch')
run(pnpm,['install','--frozen-lockfile','--ignore-scripts'],checkout,{stdio:'inherit'});run(pnpm,['run','build'],checkout,{stdio:'inherit'});run(pnpm,['pack','--pack-destination',output],checkout,{stdio:'inherit'})
const artifacts=(await readdir(output)).filter(file=>file.endsWith('.tgz'));if(artifacts.length!==1)throw new Error(`expected one Dashboard artifact, found ${artifacts.length}`)
const artifact=path.join(output,artifacts[0]);const packed=JSON.parse(run('tar',['-xOzf',artifact,'package/package.json'],root));if(packed.name!==admitted.name||packed.version!==admitted.version)throw new Error('built Dashboard artifact identity mismatch')
run('npm',['run','test:consumer'],root,{env:{...process.env,DSH_DASHBOARD_TARBALL:artifact},stdio:'inherit'})
if(run('git',['diff','--exit-code','--','.'],checkout)!=='')throw new Error('Dashboard build modified tracked source')
const artifactDigest=await digest(artifact);await rm(temporary,{recursive:true,force:true})
console.log(`Dashboard exact-source compatibility verified: ${admitted.name}@${admitted.version}, ${admitted.commit}, pnpm ${admitted.pnpm}, artifact sha256 ${artifactDigest}`)
