import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { catalogsRoot, frontend, locales } from './config.mjs';
import { digest } from './inventory.mjs';
import { validateBatch, atomicJSON } from './translate.mjs';
import { validateCatalogObject } from './schema.mjs';

export function prepareCatalogs(staging, translated, existing, policy) {
  if (digest(JSON.stringify(staging.messages)) !== translated.sourceHash) throw new Error('Staging source hash mismatch');
  for (const locale of locales.slice(1)) validateBatch(staging.messages, translated.translations[locale], locale, policy);
  const catalogs = structuredClone(existing);
  for (const [id, entry] of Object.entries(staging.messages)) {
    if (!['ui', 'direct', 'removed'].includes(entry.namespace)) throw new Error(`Unknown namespace: ${entry.namespace}`);
    if (id !== `${entry.namespace}:${entry.key}`) throw new Error(`Invalid qualified key: ${id}`);
    for (const locale of locales) {
      catalogs[entry.namespace] ??= Object.fromEntries(locales.map(language => [language, {}]));
      const catalog = catalogs[entry.namespace][locale];
      const value = locale === 'en' ? entry.message : translated.translations[locale][id];
      if (catalog[entry.key] !== undefined && catalog[entry.key] !== value) throw new Error(`Catalog conflict: ${locale}/${id}`);
      catalog[entry.key] = value;
    }
  }
  for (const bundle of Object.values(catalogs)) for (const catalog of Object.values(bundle)) validateCatalogObject(catalog);
  return catalogs;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const option = name => { const index = process.argv.indexOf(name); return index === -1 ? undefined : process.argv[index + 1]; };
  if (!option('--input') || !option('--translations')) throw new Error('Supply --input staging.json --translations translated.json; --write publishes validated bundles');
  const staging = JSON.parse(fs.readFileSync(option('--input'), 'utf8'));
  const translated = JSON.parse(fs.readFileSync(option('--translations'), 'utf8'));
  const existing = {};
  for (const namespace of ['ui', 'direct', 'removed']) existing[namespace] = Object.fromEntries(locales.map(locale => [locale, JSON.parse(fs.readFileSync(path.join(catalogsRoot, namespace, `${locale}.json`), 'utf8'))]));
  const policy = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/catalog-policy.json'), 'utf8'));
  const catalogs = prepareCatalogs(staging, translated, existing, policy);
  const aliases = {};
  for (const namespace of ['ui', 'direct', 'removed']) aliases[namespace] = JSON.parse(fs.readFileSync(path.join(catalogsRoot, namespace, 'sources.json'), 'utf8'));
  for (const entry of Object.values(staging.messages)) {
    const source = entry.locations?.[0]?.source;
    if (source && !entry.message.includes('{arg')) aliases[entry.namespace][entry.key] = source;
  }
  if (process.argv.includes('--write')) {
    for (const [namespace, bundle] of Object.entries(catalogs)) for (const [locale, catalog] of Object.entries(bundle)) atomicJSON(path.join(catalogsRoot, namespace, `${locale}.json`), catalog);
    for (const [namespace, sources] of Object.entries(aliases)) atomicJSON(path.join(catalogsRoot, namespace, 'sources.json'), sources);
  }
  console.log(JSON.stringify({ write: process.argv.includes('--write'), messages: Object.keys(staging.messages).length }));
}
