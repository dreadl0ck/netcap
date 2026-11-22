import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { frontend, sourceFilePath, parentOwned, catalogsRoot, locales } from './config.mjs';
import { digest } from './inventory.mjs';

function componentBodies(sourceFile) {
  const result = new Map();
  function visit(node) {
    if (ts.isFunctionDeclaration(node) && node.name && node.body) result.set(node.name.text, node.body);
    if (ts.isVariableDeclaration(node) && node.initializer && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
      if (ts.isBlock(node.initializer.body)) result.set(node.name.getText(), node.initializer.body);
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return result;
}

function runtimeImport(file) {
  const directory = file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n'
    : file.file.includes('/packages/netcap-ui/') ? 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n'
      : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n';
  let relative = path.posix.relative(path.posix.dirname(file.file), directory);
  if (!relative.startsWith('.')) relative = './' + relative;
  return relative;
}

/** Only isolated JSX literals inside block-bodied components are mechanical. */
export function planFile(file, text, approved) {
  if (parentOwned(file.file)) throw new Error(`Parent-owned: ${file.file}`);
  if (digest(text) !== file.sha256) throw new Error(`Source changed since inventory: ${file.file}`);
  const sourceFile = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const bodies = componentBodies(sourceFile);
  const edits = [];
  const components = new Set();
  let alias = '__netcapT';
  while (new RegExp(`\\b${alias}\\b`).test(text)) alias += '_';
  const importAlias = `${alias}Hook`;
  for (const occurrence of file.occurrences) {
    const selected = approved[occurrence.id];
    if (!selected) continue;
    if (occurrence.migration !== 'safe-jsx') throw new Error(`Needs reviewed source migration, not literal wrapping: ${occurrence.id} (${occurrence.reason})`);
    const body = bodies.get(occurrence.component);
    if (!body || occurrence.start <= body.getStart() || occurrence.end >= body.end) throw new Error(`No hook-safe component body: ${occurrence.id}`);
    let replacement = `${alias}(${JSON.stringify(selected)})`;
    if (occurrence.syntax === 'JsxText' || occurrence.reason.startsWith('jsx-attribute:')) replacement = `{${replacement}}`;
    edits.push({ start: occurrence.start, end: occurrence.end, replacement });
    components.add(occurrence.component);
  }
  if (!edits.length) return { edits, text };
  for (const component of components) {
    const body = bodies.get(component);
    // Preserve directive prologues before adding a hook.
    let position = body.getStart() + 1;
    for (const statement of body.statements) {
      if (!ts.isExpressionStatement(statement) || !ts.isStringLiteral(statement.expression)) break;
      position = statement.end;
    }
    edits.push({ start: position, end: position, replacement: `\n  const ${alias} = ${importAlias}();` });
  }
  const imports = sourceFile.statements.filter(ts.isImportDeclaration);
  const position = imports.at(-1)?.end ?? sourceFile.statements[0]?.getStart(sourceFile) ?? 0;
  edits.push({ start: position, end: position, replacement: `\nimport { useTranslate as ${importAlias} } from ${JSON.stringify(runtimeImport(file))};\n` });
  const sorted = edits.sort((a, b) => b.start - a.start);
  let boundary = text.length;
  let output = text;
  for (const edit of sorted) {
    if (edit.end > boundary) throw new Error(`Overlapping migration edits: ${file.file}`);
    output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end);
    boundary = edit.start;
  }
  const parsed = ts.createSourceFile(file.file, output, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  if (parsed.parseDiagnostics.length) throw new Error(`Migration produced invalid syntax: ${file.file}`);
  return { edits: sorted, text: output };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const index = process.argv.indexOf('--inventory');
  if (index === -1) throw new Error('Supply --inventory; rerun inventory after theme edits are complete');
  const snapshot = JSON.parse(fs.readFileSync(process.argv[index + 1], 'utf8'));
  const stageIndex = process.argv.indexOf('--staging');
  if (stageIndex === -1) throw new Error('Supply --staging with reviewed/extracted messages');
  const staging = JSON.parse(fs.readFileSync(process.argv[stageIndex + 1], 'utf8'));
  const { validateBundles } = await import('./schema.mjs');
  validateBundles(catalogsRoot, JSON.parse(fs.readFileSync(path.join(frontend, 'localization/catalog-policy.json'), 'utf8')));
  const approved = {};
  for (const [qualified, entry] of Object.entries(staging.messages)) {
    for (const locale of locales) {
      const catalog = JSON.parse(fs.readFileSync(path.join(catalogsRoot, entry.namespace, `${locale}.json`), 'utf8'));
      if (typeof catalog[entry.key] !== 'string') throw new Error(`Missing bundled ${locale} message: ${qualified}`);
    }
    for (const location of entry.locations) approved[location.id] = qualified;
  }
  const changes = [];
  const manual = [];
  for (const file of snapshot.files) {
    const selected = file.occurrences.filter(occurrence => approved[occurrence.id]);
    const safe = selected.filter(occurrence => occurrence.migration === 'safe-jsx' && !parentOwned(file.file));
    manual.push(...selected.filter(occurrence => !safe.includes(occurrence)).map(occurrence => ({ file: file.file, id: occurrence.id, reason: occurrence.reason })));
    if (!safe.length) continue;
    const absolute = sourceFilePath(file.repo, file.file);
    const text = fs.readFileSync(absolute, 'utf8');
    const result = planFile(file, text, Object.fromEntries(safe.map(occurrence => [occurrence.id, approved[occurrence.id]])));
    if (result.edits.length) changes.push({ repo: file.repo, file: file.file, absolute, ...result });
  }
  const output = { write: process.argv.includes('--write'), files: changes.map(({ file, repo, edits }) => ({ repo, file, edits })), manual };
  const outIndex = process.argv.indexOf('--out');
  if (outIndex !== -1) fs.writeFileSync(process.argv[outIndex + 1], JSON.stringify(output, null, 2) + '\n');
  // All files have been parsed and checked before the first source write.
  if (output.write) for (const change of changes) fs.writeFileSync(change.absolute, change.text);
  console.log(JSON.stringify({ write: output.write, changedFiles: changes.length, manualOccurrences: manual.length }));
}
