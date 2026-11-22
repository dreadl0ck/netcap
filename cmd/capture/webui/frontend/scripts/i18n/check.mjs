import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { catalogsRoot, frontend, sourceFilePath, parentOwned } from './config.mjs';
import { inventory, digest } from './inventory.mjs';
import { validateBundles } from './schema.mjs';

export function completionFindings(snapshot, decisions, knownMessages) {
  const findings = [];
  for (const file of snapshot.files) {
    for (const occurrence of file.occurrences) {
      if (knownMessages && occurrence.messageReference && !knownMessages.has(occurrence.source)) {
        findings.push({ repo: file.repo, file: file.file, line: occurrence.line, kind: 'missing-catalog-reference', source: occurrence.source });
      }
      if (['canonical', 'localized'].includes(occurrence.classification)) continue;
      const decision = decisions.occurrences?.[occurrence.id];
      if (decision?.action === 'keep' && decision.source === occurrence.source && decision.reason?.trim()) continue;
      findings.push({ repo: file.repo, file: file.file, line: occurrence.line, id: occurrence.id, kind: occurrence.classification, reason: occurrence.reason });
    }
    for (const kind of ['formatting', 'dynamicUI', 'dynamicTranslations', 'messageCoercions']) for (const site of file[kind] ?? []) {
      const id = digest(`${file.repo}/${file.file}\0${site.expression}`).slice(0, 24);
      const decision = decisions[kind]?.[id];
      if (decision?.expression === site.expression && decision.reason?.trim()) continue;
      findings.push({ repo: file.repo, file: file.file, line: site.line, id, kind, expression: site.expression });
    }
    const htmlReview = decisions.html?.[`${file.repo}/${file.file}`];
    if (file.html && (!htmlReview?.reason?.trim() || htmlReview.sha256 !== file.sha256)) findings.push({ repo: file.repo, file: file.file, kind: 'html' });
    const sourcePath = sourceFilePath(file.repo, file.file);
    if (!file.html && !file.file.endsWith('.json') && fs.existsSync(sourcePath)) {
      // English plural suffixes passed as message arguments produce "2 Transformations"; use ICU plural instead.
      fs.readFileSync(sourcePath, 'utf8').split('\n').forEach((line, index) => {
        if (/\?\s*(['"])(?:s|es)\1\s*:\s*(['"])\2/.test(line)) findings.push({ repo: file.repo, file: file.file, line: index + 1, kind: 'plural-suffix' });
      });
    }
  }
  return findings;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const policy = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/catalog-policy.json'), 'utf8'));
  const catalogs = validateBundles(catalogsRoot, policy);
  console.log(JSON.stringify({ catalogs }, null, 2));
  if (process.argv.includes('--handoff')) {
    const integration = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/integration.json'), 'utf8'));
    const total = catalogs.reduce((sum, item) => sum + item.messagesPerLocale, 0);
    for (const item of catalogs) if (integration.catalogStatus.namespaces[item.namespace] !== item.messagesPerLocale) throw new Error(`Stale integration count: ${item.namespace}`);
    if (integration.catalogStatus.totalMessagesPerLocale !== total || integration.catalogStatus.totalLocalizedMessages !== total * 6) throw new Error('Stale integration total');
    const artifacts = integration.localizationArtifacts;
    if (artifacts) {
      const directory = path.join(frontend, 'localization');
      const classified = new Set([...artifacts.keepForToolingAndReproducibility, ...artifacts.disposableJSON]);
      for (const file of fs.readdirSync(directory).filter(file => file.endsWith('.json'))) if (!classified.has(file)) throw new Error(`Unclassified localization artifact: ${file}`);
      for (const file of artifacts.keepForToolingAndReproducibility) if (!fs.existsSync(path.join(directory, file))) throw new Error(`Missing reproducibility input: ${file}`);
      console.log(JSON.stringify({ localizationArtifactInputs: artifacts.keepForToolingAndReproducibility.length, runtimeInputsInLocalization: artifacts.runtimeRequiredJSON.length, disposableJSON: artifacts.disposableJSON.length }));
    }
    const labels = JSON.parse(fs.readFileSync(path.join(frontend, 'packages/netcap-ui/src/lib/i18n/schema-labels.json'), 'utf8'));
    console.log(JSON.stringify({ handoff: 'validated', recordTypes: Object.keys(labels.types).length, uniqueFields: Object.keys(labels.fields).length, enumLabels: Object.keys(labels.enums).length }));
  }
  if (process.argv.includes('--complete')) {
    const decisions = JSON.parse(fs.readFileSync(path.join(frontend, 'localization/decisions.json'), 'utf8'));
    const knownMessages = new Set();
    for (const { namespace } of catalogs) {
      const english = JSON.parse(fs.readFileSync(path.join(catalogsRoot, namespace, 'en.json'), 'utf8'));
      for (const [key, source] of Object.entries(english)) { knownMessages.add(`${namespace}:${key}`); knownMessages.add(source); if (namespace === 'ui') knownMessages.add(key); }
      const aliases = JSON.parse(fs.readFileSync(path.join(catalogsRoot, namespace, 'sources.json'), 'utf8'));
      Object.values(aliases).forEach(source => knownMessages.add(source));
    }
    const all = completionFindings(inventory(), decisions, knownMessages);
    const findings = process.argv.includes('--owned') ? all.filter(item => !parentOwned(item.file)) : all;
    console.log(JSON.stringify({ scope: process.argv.includes('--owned') ? 'owned-source' : 'whole-app', unresolved: findings.length, parentOwnedFindings: all.filter(item => parentOwned(item.file)).length, byKind: Object.fromEntries([...new Set(findings.map(item => item.kind))].map(kind => [kind, findings.filter(item => item.kind === kind).length])), ...(process.argv.includes('--summary') ? {} : { findings }) }, null, 2));
    if (findings.length) process.exitCode = 1;
  }
  const snapshotIndex = process.argv.indexOf('--snapshot');
  if (snapshotIndex !== -1) {
    const snapshot = JSON.parse(fs.readFileSync(process.argv[snapshotIndex + 1], 'utf8'));
    const changed = snapshot.files.filter(file => digest(fs.readFileSync(sourceFilePath(file.repo, file.file), 'utf8')) !== file.sha256).map(file => `${file.repo}/${file.file}`);
    if (changed.length) { console.error(JSON.stringify({ staleSnapshot: changed }, null, 2)); process.exitCode = 1; }
  }
}
