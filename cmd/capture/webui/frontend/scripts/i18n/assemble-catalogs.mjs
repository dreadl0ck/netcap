import fs from 'node:fs';
import path from 'node:path';
import { frontend, locales, catalogsRoot } from './config.mjs';
import { digest } from './inventory.mjs';
import { signature, validateTranslation, validateCatalogSet } from './schema.mjs';
import { atomicJSON } from './translate.mjs';
const directory = path.join(frontend, 'localization'), stage = JSON.parse(fs.readFileSync(path.join(directory, 'full-staging.json'), 'utf8'));
const policy = JSON.parse(fs.readFileSync(path.join(directory, 'catalog-policy.json'), 'utf8'));
const banks = ['backend-translations.json', 'pro-backend-translations.json'].filter(file => fs.existsSync(path.join(directory, file))).map(file => JSON.parse(fs.readFileSync(path.join(directory, file), 'utf8')));
const reviewedFile = path.join(directory, 'reviewed-translations.json');
const reviewed = fs.existsSync(reviewedFile) ? JSON.parse(fs.readFileSync(reviewedFile, 'utf8')).messages : {};
const editionFile = path.join(directory, 'edition-classification.json');
const editionMoves = fs.existsSync(editionFile) ? JSON.parse(fs.readFileSync(editionFile, 'utf8')) : {};
const compatible = (a, b) => typeof a === 'string' && (a === b || a.replace(/\s/g, '') === b.replace(/\s/g, '') && signature(a) === signature(b));
const values = {}, missing = {}, invalid = [];
function validate(id, entry, candidate, locale) {
  // Repair a known response envelope, then enforce the same flat catalog schema.
  if (candidate && typeof candidate === 'object' && typeof candidate.message === 'string' && Object.keys(candidate).every(key => ['message', 'context'].includes(key))) candidate = candidate.message;
  validateTranslation(entry.message, candidate, locale, {
    allowUnchanged: Boolean(policy.unchanged?.[id]?.[locale] || policy.sourceUnchanged?.[entry.message]?.[locale] || policy.sourceUnchanged?.[entry.message.trim()]?.[locale]),
    tokens: (policy.technicalTokens ?? []).filter(token => entry.message.includes(token)),
  });
  return candidate;
}
for (const locale of locales.slice(1)) {
  const cacheFile = path.join(directory, `translation.${locale}.json`);
  const cache = fs.existsSync(cacheFile) ? JSON.parse(fs.readFileSync(cacheFile, 'utf8')) : { schemaVersion: 1, translations: { [locale]: {} }, sourceMessages: {}, provenance: [], failures: [], requests: 0 };
  const reverse = new Map();
  for (const [id, source] of Object.entries(cache.sourceMessages)) if (cache.translations[locale]?.[id]) reverse.set(source, cache.translations[locale][id]);
  const recovered = new Map();
  for (const failure of cache.failures ?? []) for (const item of failure.invalid ?? []) if (item.id && item.message) recovered.set(item.id, item);
  values[locale] = {}; missing[locale] = [];
  for (const [id, entry] of Object.entries(stage.messages)) {
    const candidates = [];
    // Stable backend IDs use their current six-language definitions before caches.
    for (const bank of banks) if (id.includes(':pro.') && compatible(bank.messages[id]?.message, entry.message)) {
      candidates.push(bank.translations[locale]?.[id]);
      for (const item of bank.invalid ?? []) if (item.id === id && item.locale === locale) candidates.push(item.translated);
    }
    candidates.push(reviewed[entry.message]?.[locale]);
    if (compatible(cache.sourceMessages[id], entry.message)) candidates.push(cache.translations[locale]?.[id]);
    if (entry.message.trim().length >= 15 && reverse.has(entry.message)) candidates.push(reverse.get(entry.message));
    for (const bank of banks) if (compatible(bank.messages[id]?.message, entry.message)) {
      candidates.push(bank.translations[locale]?.[id]);
      for (const item of bank.invalid ?? []) if (item.locale === locale && item.id === id) candidates.push(item.translated);
    }
    const failed = recovered.get(id);
    if (failed && compatible(failed.message, entry.message)) candidates.push(failed.translated);
    if (policy.unchanged?.[id]?.[locale] || policy.sourceUnchanged?.[entry.message]?.[locale] || policy.sourceUnchanged?.[entry.message.trim()]?.[locale]) candidates.push(entry.message);
    for (const candidate of candidates) {
      if (candidate === undefined) continue;
      try { values[locale][id] = validate(id, entry, candidate, locale); break; }
      catch (error) { invalid.push({ locale, id, source: entry.message, candidate, error: error.message }); }
    }
    if (!Object.hasOwn(values[locale], id)) missing[locale].push(id);
  }
  if (process.argv.includes('--prepare')) {
    cache.sourceHash = digest(JSON.stringify(stage.messages));
    cache.translations[locale] = values[locale];
    cache.sourceMessages = Object.fromEntries(Object.keys(values[locale]).map(id => [id, stage.messages[id].message]));
    cache.state = missing[locale].length ? 'ready-for-repair' : 'complete';
    atomicJSON(cacheFile, cache);
  }
}
atomicJSON(path.join(directory, 'translation-pending.json'), { totalMessages: Object.keys(stage.messages).length, missing, invalid });
fs.writeFileSync(path.join(directory, 'translation-review.jsonl'), Object.entries(missing).flatMap(([locale, keys]) => keys.map(id => JSON.stringify({ locale, id, source: stage.messages[id].message, context: stage.messages[id].context, location: stage.messages[id].locations[0], rejected: invalid.filter(item => item.locale === locale && item.id === id).map(item => ({ value: item.candidate, error: item.error })) }))).join('\n') + '\n');
const counts = Object.fromEntries(locales.slice(1).map(locale => [locale, { validated: Object.keys(values[locale]).length, missing: missing[locale].length }]));
if (process.argv.includes('--write')) {
  if (Object.values(missing).some(items => items.length)) throw new Error(`Incomplete translations; no runtime catalog was written: ${JSON.stringify(counts)}`);
  const prepared = [];
  for (const namespace of ['ui', 'direct', 'removed']) {
    const catalogs = Object.fromEntries(locales.map(locale => [locale, JSON.parse(fs.readFileSync(path.join(catalogsRoot, namespace, `${locale}.json`), 'utf8'))]));
    const previous = process.argv.includes('--preserve-existing') ? structuredClone(catalogs) : undefined;
    const sources = JSON.parse(fs.readFileSync(path.join(catalogsRoot, namespace, 'sources.json'), 'utf8'));
    for (const id of Object.keys(editionMoves)) if (id.startsWith(namespace + ':')) {
      const key = id.slice(namespace.length + 1);
      for (const locale of locales) delete catalogs[locale][key];
      delete sources[key];
    }
    for (const [id, entry] of Object.entries(stage.messages)) if (entry.namespace === namespace) {
      catalogs.en[entry.key] = entry.message;
      for (const locale of locales.slice(1)) catalogs[locale][entry.key] = values[locale][id];
      const source = entry.locations.find(location => typeof location.source === 'string')?.source;
      if (source && !source.includes('{arg')) sources[entry.key] = source;
    }
    if (previous) for (const locale of locales) for (const [key, value] of Object.entries(previous[locale])) {
      if (catalogs[locale][key] !== value) throw new Error(`Existing catalog changed during additive update: ${namespace}/${locale}/${key}`);
    }
    validateCatalogSet(namespace, catalogs, sources, policy);
    prepared.push({ namespace, catalogs, sources });
  }
  for (const { namespace, catalogs, sources } of prepared) {
    for (const locale of locales) atomicJSON(path.join(catalogsRoot, namespace, `${locale}.json`), catalogs[locale]);
    atomicJSON(path.join(catalogsRoot, namespace, 'sources.json'), sources);
  }
}
console.log(JSON.stringify({ messages: Object.keys(stage.messages).length, counts, runtimeCatalogsWritten: process.argv.includes('--write') }, null, 2));
