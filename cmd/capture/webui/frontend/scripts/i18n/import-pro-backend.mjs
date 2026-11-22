import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { frontend, pro, locales } from './config.mjs';
import { validateTranslation } from './schema.mjs';
const directory = path.join(frontend, 'localization'), stagePath = path.join(directory, 'full-staging.json'), stage = JSON.parse(fs.readFileSync(stagePath, 'utf8'));
const policy = JSON.parse(fs.readFileSync(path.join(directory, 'catalog-policy.json'), 'utf8'));
const bundle = { messages: {}, translations: Object.fromEntries(locales.slice(1).map(locale => [locale, {}])), invalid: [] };
const aliasPath = path.join(frontend, 'packages/netcap-ui/src/lib/i18n/backend-ids.json'), aliases = JSON.parse(fs.readFileSync(aliasPath, 'utf8'));
const routesFile = path.join(pro, 'frontend/src/routes.appstore.tsx');
const routes = ts.createSourceFile(routesFile, fs.readFileSync(routesFile, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX), appStoreRoutes = new Set();
function collectRoutes(node) {
  if ((ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node)) && node.tagName.getText(routes) === 'Route') for (const attribute of node.attributes.properties) if (ts.isJsxAttribute(attribute) && attribute.name.getText(routes) === 'path' && attribute.initializer && ts.isStringLiteral(attribute.initializer)) appStoreRoutes.add(attribute.initializer.text);
  ts.forEachChild(node, collectRoutes);
}
collectRoutes(routes);
const scopes = {};
let count = 0;
for (const service of ['similarity', 'graph']) {
  const file = `services/${service}/presentation.json`, source = JSON.parse(fs.readFileSync(path.join(pro, file), 'utf8'));
  if (source.namespace !== 'direct' || source.locales.join() !== locales.join()) throw new Error(`Unexpected namespace/locale order: ${file}`);
  const namespace = appStoreRoutes.has(`/${service}`) ? 'ui' : 'removed';
  scopes[service] = namespace;
  for (const [key, row] of Object.entries(source.messages)) {
    if (!Array.isArray(row) || row.length !== locales.length || row.some(value => typeof value !== 'string' || !value.trim())) throw new Error(`Invalid six-column row: ${file}/${key}`);
    const id = `${namespace}:${key}`, entry = { namespace, key, message: row[0], context: `Authoritative six-language backend descriptor for ${service}; MAS route ${appStoreRoutes.has(`/${service}`) ? 'retained' : 'absent'}. Evidence parameters remain raw.`, locations: [{ repo: 'netcap-pro', file, line: 1, source: row[0] }] };
    stage.messages[id] = entry; bundle.messages[id] = entry;
    aliases[`${source.namespace}:${key}`] = id;
    for (let index = 1; index < 6; index++) {
      const locale = locales[index];
      const reviewed = Object.entries(stage.messages).find(([otherID, other]) => other.message === row[0] && policy.unchanged?.[otherID]?.[locale]);
      if (reviewed && row[index] === row[0]) { policy.unchanged[id] ??= {}; policy.unchanged[id][locale] ??= `Same reviewed native term/cognate as ${reviewed[0]}.`; }
      try { validateTranslation(row[0], row[index], locale, { allowUnchanged: Boolean(policy.unchanged?.[id]?.[locale] || policy.sourceUnchanged?.[row[0]]?.[locale]), tokens: [] }); bundle.translations[locale][id] = row[index]; }
      catch (error) { bundle.invalid.push({ locale, id, source: row[0], translated: row[index], error: error.message }); }
    }
    count++;
  }
}
fs.writeFileSync(stagePath, JSON.stringify(stage, null, 2) + '\n');
fs.writeFileSync(aliasPath, JSON.stringify(aliases, null, 2) + '\n');
fs.writeFileSync(path.join(directory, 'pro-backend-translations.json'), JSON.stringify(bundle, null, 2) + '\n');
fs.writeFileSync(path.join(directory, 'catalog-policy.json'), JSON.stringify(policy, null, 2) + '\n');
console.log(JSON.stringify({ proBackendMessages: count, namespaceByMASRoute: scopes, timelineRetained: appStoreRoutes.has('/timeline'), invalidTargetsForReview: bundle.invalid.length }));
