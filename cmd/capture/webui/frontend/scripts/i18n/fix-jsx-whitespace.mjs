import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned, locales } from './config.mjs';
import { inventory } from './inventory.mjs';
import { signature } from './schema.mjs';
const directory = path.join(frontend, 'localization');
const old = JSON.parse(fs.readFileSync(path.join(directory, 'whitespace-old.json'), 'utf8'));
const corrected = JSON.parse(fs.readFileSync(path.join(directory, 'whitespace-corrected.json'), 'utf8'));
const stagePath = path.join(directory, 'full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const byPosition = new Map();
for (const [id, entry] of Object.entries(corrected.messages)) for (const location of entry.locations) byPosition.set(`${location.repo}/${location.file}:${location.offset}:${entry.context}`, { id, entry });
const replacements = new Map(), conflicts = [];
for (const [oldID, entry] of Object.entries(old.messages)) {
  for (const location of entry.locations) {
    const next = byPosition.get(`${location.repo}/${location.file}:${location.offset}:${entry.context}`);
    if (!next || next.id === oldID || !stage.messages[oldID]) continue;
    if (entry.message.replace(/\s/g, '') !== next.entry.message.replace(/\s/g, '') || signature(entry.message) !== signature(next.entry.message)) continue;
    if (replacements.has(oldID) && replacements.get(oldID).id !== next.id) { conflicts.push({ oldID, alternatives: [replacements.get(oldID).id, next.id], source: entry.message }); continue; }
    replacements.set(oldID, next);
  }
}
// Keep published source IDs stable through a whitespace-only English copy correction.
for (const [oldID, { entry }] of replacements) stage.messages[oldID] = { ...stage.messages[oldID], message: entry.message };
const files = 0;
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(directory, 'jsx-whitespace-repair.json'), JSON.stringify({ files, messages: replacements.size, conflicts }, null, 2) + '\n');
console.log(JSON.stringify({ files, correctedMessages: replacements.size, ambiguousWhitespaceContexts: conflicts.length }));
