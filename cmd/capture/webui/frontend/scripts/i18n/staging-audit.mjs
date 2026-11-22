import fs from 'node:fs';
import path from 'node:path';
import { frontend } from './config.mjs';
import { signature } from './schema.mjs';

const file = process.argv[2] ?? path.join(frontend, 'localization/full-staging.json');
const stage = JSON.parse(fs.readFileSync(file, 'utf8'));
const errors = [];
const counts = {};
for (const [key, entry] of Object.entries(stage.messages)) {
  counts[entry.namespace] = (counts[entry.namespace] ?? 0) + 1;
  try { signature(entry.message); } catch (error) { errors.push({ key, message: entry.message, error: error.message, locations: entry.locations }); }
}
fs.writeFileSync(path.join(frontend, 'localization/staging-errors.json'), JSON.stringify(errors, null, 2) + '\n');
console.log(JSON.stringify({ messages: Object.keys(stage.messages).length, counts, invalidICU: errors.length }, null, 2));
if (errors.length) process.exitCode = 1;
