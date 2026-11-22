import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';

const snapshot = inventory();
const changed = [];
for (const file of snapshot.files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json') || /\/(?:preferences|Preferences|PresentationControls|AppearanceControls)/.test(file.file)) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8');
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], imported = new Set();
  let module = file.repo === 'netcap-pro' ? path.posix.relative(path.posix.dirname(file.file), 'frontend/src/lib/i18n') : path.posix.relative(path.posix.dirname(file.file), 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n');
  if (!module.startsWith('.')) module = './' + module;
  const add = (node, replacement, reason) => edits.push({ start: node.getStart(sf), end: node.end, replacement, reason });
  function visit(node) {
    if (ts.isImportDeclaration(node) && node.moduleSpecifier.text === 'swr') {
      const clause = node.importClause;
      if (clause?.name) {
        imported.add(`usePresentationSWR as ${clause.name.text}`);
        const named = clause.namedBindings && ts.isNamedImports(clause.namedBindings) ? clause.namedBindings.elements : [];
        const remaining = [];
        for (const item of named) {
          if ((item.propertyName?.text ?? item.name.text) === 'mutate') imported.add(`mutatePresentation as ${item.name.text}`);
          else remaining.push(item.getText(sf));
        }
        add(node, remaining.length ? `import { ${remaining.join(', ')} } from 'swr';` : '', 'locale-scoped-swr-cache');
      }
    }
    // App-owned backend metadata has additive presentation fields; evidence does not.
    if (ts.isPropertyAccessExpression(node)) {
      const owner = node.expression.getText(sf), field = node.name.text;
      const metadata = (/^(?:feature|option|decoder|harvester|parameter|param|fieldInfo|chartField|coverage|capability|template)$/.test(owner)
        && ['title', 'description', 'scope', 'category', 'label', 'help', 'typeDescription'].includes(field));
      const display = (() => {
        for (let p = node.parent; p; p = p.parent) {
          if (ts.isBinaryExpression(p) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(p.operatorToken.kind)) return false;
          if (ts.isCallExpression(p) && /(?:includes|toLowerCase|filter|sort|^api\.)/.test(p.expression.getText(sf))) return false;
          if (ts.isStatement(p)) return false;
          if (ts.isJsxExpression(p)) {
            if (ts.isJsxAttribute(p.parent) && !/^(?:label|title|placeholder|helperText|primary|secondary|data-learn|aria-label|aria-description|slotProps)$/.test(p.parent.name.getText(sf))) return false;
            return true;
          }
        }
        return false;
      })();
      if (metadata && display) { imported.add('metadataText'); add(node, `metadataText(${owner}, ${JSON.stringify(field)})`, 'backend-ui-message-field'); return; }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  // The shared API preserves transport values and adds a request-local locale.
  if (file.file.endsWith('/src/lib/api.ts')) {
    imported.add('localeURL');
    const fn = sf.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'createApiWithBase');
    if (fn?.body) edits.push({ start: fn.body.getStart(sf) + 1, end: fn.body.getStart(sf) + 1, replacement: `\n  const fetch: typeof globalThis.fetch = (input, init) => globalThis.fetch(typeof input === 'string' && input.startsWith(apiBase) ? localeURL(input) : input, init);\n`, reason: 'request-local-backend-presentation' });
  }
  if (!edits.length) continue;
  if (imported.size) {
    const imports = sf.statements.filter(ts.isImportDeclaration), position = imports.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start: position, end: position, replacement: `\nimport { ${[...imported].join(', ')} } from ${JSON.stringify(module)};\n`, reason: 'localization-imports' });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) {
    if (edit.end > boundary) throw new Error(`Overlapping refinements: ${file.file}`);
    output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start;
  }
  fs.writeFileSync(absolute, output);
  changed.push({ repo: file.repo, file: file.file, edits: edits.map(({ reason, start }) => ({ reason, line: sf.getLineAndCharacterOfPosition(start).line + 1 })) });
}
fs.writeFileSync(path.join(frontend, 'localization/source-refinements.json'), JSON.stringify(changed, null, 2) + '\n');
console.log(JSON.stringify({ refinedFiles: changed.length }));
