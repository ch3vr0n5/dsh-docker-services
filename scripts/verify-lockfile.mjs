import {readFile} from 'node:fs/promises'

const lock = JSON.parse(await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'))
if (lock.lockfileVersion !== 3 || !lock.packages || typeof lock.packages !== 'object') throw new Error('package-lock.json must be a v3 npm lock')
let registryPackages = 0
for (const [location, value] of Object.entries(lock.packages)) {
  if (!location.startsWith('node_modules/') || value.link === true) continue
  registryPackages += 1
  if (typeof value.version !== 'string' || typeof value.resolved !== 'string' || !value.resolved.startsWith('https://registry.npmjs.org/') || typeof value.integrity !== 'string' || !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(value.integrity)) throw new Error(`dependency is not content-pinned: ${location}`)
}
if (registryPackages < 1) throw new Error('lockfile contains no pinned registry packages')
console.log(`verified ${registryPackages} content-pinned registry packages`)
