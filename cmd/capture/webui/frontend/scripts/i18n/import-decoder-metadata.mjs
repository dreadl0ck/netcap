import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { frontend, netcap } from './config.mjs';
import { stableKey, escapeICU } from './inventory.mjs';
const tool = path.join(frontend, 'scripts/i18n/extract-metadata.go');
const rows = JSON.parse(execFileSync('go', ['run', tool, netcap], { cwd: '/var/folders/sb/n7njgj0s1ln8wkb4j9hs4n8h0000gn/T/opencode', env: { ...process.env, GOTOOLCHAIN: 'local', GO111MODULE: 'off', GOWORK: 'off' }, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
const file = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(file, 'utf8'));
const unique = new Set();
for (const row of rows) {
  const message = escapeICU(row.source), key = stableKey(message), id = `ui:${key}`;
  stage.messages[id] ??= { namespace: 'ui', key, message, context: 'Built-in protocol decoder / credential-harvester documentation shown in the frontend. Protocol names and syntax stay unchanged.', locations: [] };
  stage.messages[id].locations.push({ repo: 'netcap', file: row.file, line: row.line, source: row.source, rationale: `Go AST ${row.kind}; no captured/user strings are extracted.` });
  unique.add(id);
}
fs.writeFileSync(file, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/decoder-metadata-inventory.json'), JSON.stringify(rows, null, 2) + '\n');
console.log(JSON.stringify({ goASTDocumentationSites: rows.length, uniqueDocumentationMessages: unique.size }));
