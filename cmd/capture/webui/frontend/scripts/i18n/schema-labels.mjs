import fs from 'node:fs';
import path from 'node:path';
import { frontend, netcap } from './config.mjs';
import { stableKey, escapeICU, digest } from './inventory.mjs';

// A lexical protobuf reader, skipping comments/quoted options before declaration parsing.
const source = fs.readFileSync(path.join(netcap, 'types/netcap.proto'), 'utf8');
const tokens = [];
for (let index = 0; index < source.length;) {
  const char = source[index];
  if (/\s/.test(char)) { index++; continue; }
  if (source.startsWith('//', index)) { index = source.indexOf('\n', index); if (index < 0) break; continue; }
  if (source.startsWith('/*', index)) { index = source.indexOf('*/', index + 2) + 2; continue; }
  if (char === '"' || char === "'") { const quote = char; index++; while (index < source.length) { if (source[index++] === '\\') { index++; continue; } if (source[index - 1] === quote) break; } tokens.push('STRING'); continue; }
  if (/[A-Za-z_\d]/.test(char)) { const start = index++; while (index < source.length && /[A-Za-z_\d]/.test(source[index])) index++; tokens.push(source.slice(start, index)); continue; }
  tokens.push(char); index++;
}
const types = new Set(), fields = new Set();
for (let index = 0; index < tokens.length; index++) {
  if (tokens[index] === 'message' && tokens[index + 2] === '{') {
    types.add(tokens[index + 1]);
    let depth = 1, statement = [];
    for (index += 3; index < tokens.length && depth; index++) {
      const token = tokens[index];
      if (token === '{') depth++;
      if (token === '}') depth--;
      if (depth !== 1) continue;
      if (token === ';') {
        const equals = statement.indexOf('=');
        if (equals >= 2 && !['option', 'reserved', 'extensions'].includes(statement[0]) && /^[A-Za-z_]\w*$/.test(statement[equals - 1])) fields.add(statement[equals - 1]);
        statement = [];
      } else statement.push(token);
    }
    index--;
  }
}
const overrides = { SrcIP: 'Source IP address', DstIP: 'Destination IP address', SrcPort: 'Source port', DstPort: 'Destination port', SrcMAC: 'Source MAC address', DstMAC: 'Destination MAC address', NumPackets: 'Packet count', Timestamp: 'Timestamp', TimestampFirst: 'First timestamp', TimestampLast: 'Last timestamp', CommunityID: 'Community ID', JA4: 'JA4', OS: 'Operating system', IsSelfSigned: 'Self-signed', IsKnownMalware: 'Known malware', BytesClientToServer: 'Client-to-server bytes', BytesServerToClient: 'Server-to-client bytes', TLSServerHello: 'TLS ServerHello', TLSClientHello: 'TLS ClientHello' };
const friendly = id => overrides[id] ?? id.replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2').replace(/([a-z\d])([A-Z])/g, '$1 $2').replace(/_/g, ' ');
const stagePath = path.join(frontend, 'localization/full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const labels = { types: {}, fields: {}, enums: {} };
function label(id, english, category) {
  if (/^[A-Z\d]+s?$/.test(english)) { labels[category][id] = { literal: english }; return; }
  const message = escapeICU(english), key = stableKey(message), qualified = `ui:${key}`;
  stage.messages[qualified] ??= { namespace: 'ui', key, message, context: '', locations: [{ repo: 'netcap', file: 'types/netcap.proto', line: 1, source: english, rationale: 'Known schema identifier display label; canonical identifier remains unchanged.' }] };
  labels[category][id] = { key: qualified };
}
for (const type of [...types].sort()) label(type, friendly(type), 'types');
for (const field of [...fields].sort()) label(field, friendly(field), 'fields');
const enums = { active: 'Active', inactive: 'Inactive', enabled: 'Enabled', disabled: 'Disabled', connected: 'Connected', disconnected: 'Disconnected', connecting: 'Connecting', reconnecting: 'Reconnecting', pending: 'Pending', complete: 'Complete', incomplete: 'Incomplete', failed: 'Failed', error: 'Error', warning: 'Warning', critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational', informational: 'Informational', unknown: 'Unknown', unavailable: 'Unavailable', verified: 'Verified', legacy: 'Legacy', missing: 'Missing', ambiguous: 'Ambiguous', overflow: 'Overflow', retained: 'Retained', live: 'Live', none: 'None', table: 'Table', graph: 'Graph', timeline: 'Timeline', column: 'Column', ascending: 'Ascending', descending: 'Descending', client: 'Client', server: 'Server', inbound: 'Inbound', outbound: 'Outbound', bidirectional: 'Bidirectional', untagged: 'Untagged' };
for (const [id, english] of Object.entries(enums)) label(id, english, 'enums');
const output = path.join(frontend, 'packages/netcap-ui/src/lib/i18n/schema-labels.json');
fs.writeFileSync(output, JSON.stringify(labels, null, 2) + '\n');
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(frontend, 'localization/schema-label-inventory.json'), JSON.stringify({ schema: 'types/netcap.proto', sha256: digest(source), recordTypeDeclarations: types.size, uniqueFieldDeclarations: fields.size, enumLabels: Object.keys(enums).length }, null, 2) + '\n');
console.log(JSON.stringify({ recordTypes: types.size, fields: fields.size, catalogMessages: Object.keys(stage.messages).length }));
