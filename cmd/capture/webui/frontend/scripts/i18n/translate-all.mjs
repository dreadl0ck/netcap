import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { frontend, locales } from './config.mjs';
import { digest } from './inventory.mjs';
import { geminiKey, translateBatch, validateBatch, atomicJSON } from './translate.mjs';

const directory = path.join(frontend, 'localization');
const languages = locales.slice(1);
const statusFile = locale => path.join(directory, `translation.${locale}.json`);
if (process.argv.includes('--status')) {
  console.log(JSON.stringify(languages.map(locale => {
    if (!fs.existsSync(statusFile(locale))) return { locale, state: 'not-started' };
    const result = JSON.parse(fs.readFileSync(statusFile(locale), 'utf8'));
    return { locale, state: result.state, translated: Object.keys(result.translations[locale] ?? {}).length, requests: result.requests, ...(process.argv.includes('--summary') ? { failedBatches: result.failures?.length ?? 0 } : { failures: result.failures?.slice(-3).map(failure => ({ error: failure.error, invalid: failure.invalid })) }) };
  }), null, 2));
} else if (process.argv.includes('--background')) {
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url)], { detached: true, stdio: 'ignore', env: process.env });
  child.unref(); console.log(JSON.stringify({ pid: child.pid, status: 'node scripts/i18n/translate-all.mjs --status' }));
} else {
  const staging = JSON.parse(fs.readFileSync(path.join(directory, 'full-staging.json'), 'utf8'));
  const policy = JSON.parse(fs.readFileSync(path.join(directory, 'catalog-policy.json'), 'utf8'));
  const glossary = JSON.parse(fs.readFileSync(path.join(directory, 'glossary.json'), 'utf8'));
  const key = geminiKey();
  if (!key) throw new Error('GEMINI_API_KEY is unavailable');
  const sourceHash = digest(JSON.stringify(staging.messages));
  async function worker(locale) {
    const result = fs.existsSync(statusFile(locale)) ? JSON.parse(fs.readFileSync(statusFile(locale), 'utf8')) : { schemaVersion: 1, translations: { [locale]: {} }, sourceMessages: {}, provenance: [], failures: [], requests: 0 };
    result.state = 'running'; result.sourceHash = sourceHash; result.requests = 0; result.failures = [];
    for (const [id, translated] of Object.entries(result.translations[locale])) {
      if (!staging.messages[id] || result.sourceMessages[id] !== staging.messages[id].message) { delete result.translations[locale][id]; continue; }
      try { validateBatch({ [id]: staging.messages[id] }, { [id]: translated }, locale, policy); }
      catch { delete result.translations[locale][id]; }
    }
    const remaining = Object.entries(staging.messages).filter(([id]) => !Object.hasOwn(result.translations[locale], id));
    const batches = [];
    for (let index = 0; index < remaining.length; index += 40) batches.push(remaining.slice(index, index + 40));
    // One initial request and at most two repairs per message, bounded overall.
    const budget = Math.min(700, batches.length * 5 + 30);
    atomicJSON(statusFile(locale), result);
    async function batch(entries, repairs = 0) {
      if (!entries.length || result.requests >= budget) return;
      result.requests += 1;
      try {
        const translated = await translateBatch(Object.fromEntries(entries), locale, { key, model: process.env.NETCAP_TRANSLATION_MODEL ?? 'gemini-3-flash-preview', policy: JSON.parse(fs.readFileSync(path.join(directory, 'catalog-policy.json'), 'utf8')), glossary, attempts: 1, partial: true });
        Object.assign(result.translations[locale], translated.translated);
        for (const [id, entry] of entries) result.sourceMessages[id] = entry.message;
        result.provenance.push({ locale, keys: entries.map(([id]) => id), modelVersion: translated.modelVersion, usage: translated.usage });
        if (translated.invalid.length) {
          result.failures.push({ invalid: translated.invalid });
          atomicJSON(statusFile(locale), result);
          if (repairs < 2) await batch(entries.filter(([id]) => translated.invalid.some(item => item.id === id)), repairs + 1);
        }
      } catch (error) {
        result.failures.push({ keys: entries.map(([id]) => id), error: error.message });
        atomicJSON(statusFile(locale), result);
        if (repairs < 2) {
          const middle = Math.ceil(entries.length / 2);
          await batch(entries.slice(0, middle), repairs + 1);
          await batch(entries.slice(middle), repairs + 1);
        }
      }
      atomicJSON(statusFile(locale), result);
    }
    for (const entries of batches) await batch(entries);
    result.state = Object.keys(staging.messages).every(id => Object.hasOwn(result.translations[locale], id)) ? 'complete' : 'needs-repair';
    atomicJSON(statusFile(locale), result);
  }
  await Promise.all(languages.map(worker));
}
