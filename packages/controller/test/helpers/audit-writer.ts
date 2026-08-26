import {AuditLog, KeyedFileCheckpointSink} from '../../src/state.js'

const [state, checkpoint, keyFile, actor, rawCount] = process.argv.slice(2)
if (!state || !checkpoint || !keyFile || !actor || !rawCount) throw new Error('missing audit writer arguments')
const count = Number(rawCount)
const audit = await AuditLog.create(state, await KeyedFileCheckpointSink.create(checkpoint, keyFile))
for (let index = 0; index < count; index += 1) await audit.append({actor, capability: 'services:read', action: `inventory-${index}`, outcome: 'ok'})
