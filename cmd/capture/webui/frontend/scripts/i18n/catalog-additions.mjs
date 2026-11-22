import fs from 'node:fs';
import path from 'node:path';
import { frontend, pro } from './config.mjs';
import { stableKey } from './inventory.mjs';
const directory = path.join(frontend, 'localization'), stagePath = path.join(directory, 'full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
stage.messages['ui:rules.failedCount'] = { namespace: 'ui', key: 'rules.failedCount', message: '{count, plural, one {# rule failed} other {# rules failed}}', context: 'Deferred batch evaluation summary.', locations: [{ repo: 'netcap', file: 'cmd/capture/webui/frontend/packages/netcap-ui/src/pages/RulesPage.tsx', line: 1, source: '{count} rules failed' }] };
for (const [key, message] of Object.entries({
  'graph.batch.failedSingle': 'Transform failed: {detail}',
  'graph.batch.failedAll': '{count, plural, one {Transform failed on the selected node: {detail}} other {Transform failed on all # nodes: {detail}}}',
  'graph.batch.moreErrors': '{count, plural, one {(+ # more error)} other {(+ # more errors)}}',
  'graph.batch.partial': 'Transform results — succeeded: {succeeded}; entities: {entities}; failed: {failed}. {detail}',
  'graph.batch.done': '{name}: done',
  'graph.batch.noEntitiesInfo': 'Transform completed: no entities found ({detail})',
  'graph.batch.foundEntities': '{count, plural, one {Transform completed: # entity found} other {Transform completed: # entities found}}',
  'graph.batch.undo': '(CMD-Z to undo)',
  'graph.batch.results': 'Transform results — nodes: {success}/{total}; entities: {entities}; edges: {edges}',
})) stage.messages[`removed:${key}`] = { namespace: 'removed', key, message, context: 'Deferred graph batch notification; parameters include raw evidence and other localized descriptors.', locations: [{ repo: 'netcap-pro', file: 'frontend/src/pages/graph.tsx', line: 1, source: message }] };
for (const [key, message] of Object.entries({ 'defaults.machineName': 'New Machine', 'defaults.stepName': 'Step {number}' })) stage.messages[`removed:${key}`] = { namespace: 'removed', key, message, context: 'Default name created in the selected locale. User-edited/saved names never translate.', locations: [{ repo: 'netcap-pro', file: 'frontend/src/lib/machineTypes.ts', line: 1, source: message }] };
const labelFile = path.join(frontend, 'packages/netcap-ui/src/lib/i18n/schema-labels.json'), labels = JSON.parse(fs.readFileSync(labelFile, 'utf8'));
const literal = { Uri: 'URI', Xid: 'XID', Ja4: 'JA4', Ja4S: 'JA4S', Ja4H: 'JA4H', Ja4X: 'JA4X', Ja4T: 'JA4T', Ja4Ts: 'JA4TS', Ja4ssh: 'JA4SSH', JA4D: 'JA4D', ALPNs: 'ALPNs', AVPs: 'AVPs', Ndpi: 'nDPI', ContentSecurityPolicy: 'Content-Security-Policy', StrictTransportSecurity: 'Strict-Transport-Security', UserAgent: 'User-Agent', XContentTypeOptions: 'X-Content-Type-Options', XForwardedFor: 'X-Forwarded-For', XFrameOptions: 'X-Frame-Options', XOriginatingIP: 'X-Originating-IP', XPoweredBy: 'X-Powered-By', XRealIP: 'X-Real-IP', XXSSProtection: 'X-XSS-Protection' };
const rewritten = { TSval: 'TCP timestamp value', TSecr: 'TCP timestamp echo reply', Will: 'MQTT will flag', WillTopic: 'MQTT will topic', WillRetain: 'MQTT will-retain flag', WillMessage: 'MQTT will message', Ems: 'Extended master secret (EMS)', Id: 'Identifier', Ident: 'Identifier', Cmd: 'Command', Ctrl: 'Control field', OrgTLVs: 'Organization-specific TLVs' };
const oldKeys = new Set();
for (const id of ['learning', 'monitoring', 'paused']) labels.enums[id] = { key: `ui:status.${id}` };
if (labels.fields.Ack) { if (labels.fields.Ack.key) oldKeys.add(labels.fields.Ack.key); labels.fields.Ack = { literal: 'ACK' }; }
for (const [id, text] of Object.entries({ BACnetIP: 'BACnet/IP', VRRPv2: 'VRRPv2', Dot11ASEL: '802.11 ASEL', Dot11QOS: '802.11 QoS' })) if (labels.types[id]) { if (labels.types[id].key) oldKeys.add(labels.types[id].key); labels.types[id] = { literal: text }; }
for (const [id, text] of Object.entries(literal)) if (labels.fields[id]) { if (labels.fields[id].key) oldKeys.add(labels.fields[id].key); labels.fields[id] = { literal: text }; }
for (const [id, message] of Object.entries(rewritten)) if (labels.fields[id]) {
  if (labels.fields[id].key) oldKeys.add(labels.fields[id].key);
  const key = stableKey(message); labels.fields[id] = { key: `ui:${key}` };
  stage.messages[`ui:${key}`] ??= { namespace: 'ui', key, message, context: 'Protocol-specific schema display label. Translate descriptive words and retain acronyms; MQTT Will is a protocol field.', locations: [{ repo: 'netcap', file: 'types/netcap.proto', line: 1, source: message }] };
}
const retained = new Set(Object.values(labels.fields).flatMap(value => value.key ? [value.key] : []).concat(Object.values(labels.types).flatMap(value => value.key ? [value.key] : [])));
for (const key of oldKeys) if (!retained.has(key) && stage.messages[key]?.locations.every(location => location.file === 'types/netcap.proto')) delete stage.messages[key];
fs.writeFileSync(labelFile, JSON.stringify(labels, null, 2) + '\n');
const aliasesFile = path.join(frontend, 'packages/netcap-ui/src/lib/i18n/backend-ids.json'), aliases = JSON.parse(fs.readFileSync(aliasesFile, 'utf8'));
const find = text => Object.entries(stage.messages).find(([, entry]) => entry.message === text)?.[0];
for (const [code, text] of Object.entries({ packet: 'Packet decoder', gopacket: 'Packet decoder (gopacket)', stream: 'Stream decoder', abstract: 'Abstract decoder' })) if (find(text)) aliases[`decoder.type.${code}`] = find(text);
for (const [id, text] of Object.entries({ 'feature.scope.query': 'Next API request', 'feature.scope.capture': 'Next capture analysis', 'ruleset.enabled': 'Rule set {name} enabled ({count} rules affected)', 'ruleset.disabled': 'Rule set {name} disabled ({count} rules affected)', 'injection.rule.enabled': 'Injection rule enabled', 'injection.rule.disabled': 'Injection rule disabled' })) if (find(text)) aliases[id] = find(text);
// Mac App Store highlights are copied only from existing, applicable release notes.
const appStore = JSON.parse(fs.readFileSync(path.join(pro, 'frontend/src/lib/releaseHighlights.appstore.json'), 'utf8'));
for (const entries of Object.values(appStore)) for (const item of entries) for (const message of [item.title, item.description]) {
  const key = stableKey(message);
  stage.messages[`ui:${key}`] ??= { namespace: 'ui', key, message, context: 'Existing Mac App Store-applicable release highlight.', locations: [{ repo: 'netcap-pro', file: 'frontend/src/lib/releaseHighlights.appstore.json', line: 1, source: message }] };
}
fs.writeFileSync(aliasesFile, JSON.stringify(aliases, null, 2) + '\n');
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
console.log(JSON.stringify({ catalogMessages: Object.keys(stage.messages).length, standardizedProtocolHeaders: Object.keys(literal).length }));
