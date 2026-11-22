import fs from 'node:fs';
import path from 'node:path';
import { frontend, netcap, locales } from './config.mjs';
import { stableKey, escapeICU } from './inventory.mjs';
import { validateTranslation } from './schema.mjs';
const directory = path.join(frontend, 'localization'), stagePath = path.join(directory, 'full-staging.json');
const stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const policy = JSON.parse(fs.readFileSync(path.join(directory, 'catalog-policy.json'), 'utf8'));
const bundle = { messages: {}, translations: Object.fromEntries(locales.slice(1).map(locale => [locale, {}])), invalid: [] };
const sourceIDs = new Map();
function tokens(source) {
  const result = [];
  for (let index = 0; index < source.length;) {
    if (/\s/.test(source[index])) { index++; continue; }
    if (source.startsWith('//', index)) { index = source.indexOf('\n', index); if (index === -1) break; continue; }
    if (source.startsWith('/*', index)) { index = source.indexOf('*/', index + 2) + 2; continue; }
    if (source[index] === '"') {
      const start = index++;
      while (index < source.length) { if (source[index++] === '\\') index++; else if (source[index - 1] === '"') break; }
      let text;
      try { text = JSON.parse(source.slice(start, index)); } catch { text = undefined; }
      result.push({ type: 'string', text, offset: start }); continue;
    }
    result.push({ type: source[index], text: source[index], offset: index }); index++;
  }
  return result;
}
function pattern(text) {
  let result = '', start = 0;
  for (const match of text.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)) {
    result += escapeICU(text.slice(start, match.index)) + `{${match[1]}}`; start = match.index + match[0].length;
  }
  return result + escapeICU(text.slice(start));
}
let imported = 0;
for (const filename of ['presentation_metadata_catalog.go', 'presentation_catalog.go']) {
  const relative = `cmd/capture/webui/${filename}`, source = fs.readFileSync(path.join(netcap, relative), 'utf8'), stream = tokens(source);
  for (let index = 0; index < stream.length - 3; index++) {
    if (stream[index].type !== 'string' || stream[index + 1].type !== ':' || stream[index + 2].type !== '{') continue;
    const sourceText = stream[index].text, translated = [];
    if (sourceText === undefined) throw new Error(`Non-text backend catalog source in ${filename}`);
    let cursor = index + 3;
    while (cursor < stream.length && stream[cursor].type !== '}') { if (stream[cursor].type === 'string') translated.push(stream[cursor].text); cursor++; }
    if (translated.length !== 5) throw new Error(`Invalid backend catalog row: ${sourceText}`);
    const namespace = /\b(?:DPI|YARA|Hyperscan|injection|live capture|database download|geolocation providers)\b/i.test(sourceText) ? 'removed' : 'ui';
    let message = pattern(sourceText);
    const plural = message.match(/\{count\} (file|alert)\(s\)/);
    if (plural) message = message.replace(plural[0], `{count, plural, one {# ${plural[1]}} other {# ${plural[1]}s}}`);
    if (message === '{count} harvesters configured') message = '{count, plural, one {# harvester configured} other {# harvesters configured}}';
    const key = stableKey(message), id = `${namespace}:${key}`;
    sourceIDs.set(sourceText, id);
    const entry = { namespace, key, message, context: '', locations: [{ repo: 'netcap', file: relative, line: source.slice(0, stream[index].offset).split('\n').length, source: sourceText, rationale: 'Backend-owned presentation source; not captured/user content.' }] };
    stage.messages[id] ??= entry; bundle.messages[id] = entry;
    for (let language = 0; language < 5; language++) {
      const locale = locales[language + 1], target = pattern(translated[language]);
      try { validateTranslation(message, target, locale, { allowUnchanged: Boolean(policy.sourceUnchanged?.[message]?.[locale] || policy.unchanged?.[id]?.[locale]), tokens: [] }); }
      catch (error) { bundle.invalid.push({ locale, id, source: message, translated: target, error: error.message }); continue; }
      bundle.translations[locale][id] = target;
    }
    imported++; index = cursor;
  }
}
const aliases = {};
const directoryGo = path.join(netcap, 'cmd/capture/webui');
for (const filename of fs.readdirSync(directoryGo).filter(name => name.endsWith('.go') && !name.endsWith('_test.go'))) {
  const code = fs.readFileSync(path.join(directoryGo, filename), 'utf8'), stream = tokens(code);
  for (let index = 0; index < stream.length - 2; index++) {
    if (stream[index].type !== 'string' || stream[index + 1].type !== ',' || stream[index + 2].type !== 'string') continue;
    const prefix = code.slice(Math.max(0, stream[index].offset - 180), stream[index].offset);
    if (!/(?:requestUIMessage|\.message)\([^()]*$/.test(prefix)) continue;
    const id = stream[index].text, source = stream[index + 2].text;
    if (typeof id === 'string' && sourceIDs.has(source)) aliases[id] = sourceIDs.get(source);
  }
}
fs.writeFileSync(path.join(frontend, 'packages/netcap-ui/src/lib/i18n/backend-ids.json'), JSON.stringify(aliases, null, 2) + '\n');
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(path.join(directory, 'backend-translations.json'), JSON.stringify(bundle, null, 2) + '\n');
console.log(JSON.stringify({ reusedBackendMessages: imported, backendMessageIDs: Object.keys(aliases).length, invalidTargetsForReview: bundle.invalid.length }));
