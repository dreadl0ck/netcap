import ts from 'typescript';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { frontend, roots, productionRoots, htmlFiles, parentOwned, namespaceFor } from './config.mjs';

export const digest = text => createHash('sha256').update(text).digest('hex');
export const stableKey = (message, context = '') => `m_${digest(context + '\0' + message).slice(0, 20)}`;
const displayNames = new Set(['label', 'title', 'description', 'helperText', 'placeholder', 'alt', 'summary', 'primary', 'secondary', 'question', 'caption', 'tooltip', 'emptyText', 'noOptionsText', 'loadingText', 'name', 'message', 'headerName', 'displayName', 'text', 'unit', 'category']);
const canonicalNames = new Set(['id', 'key', 'type', 'field', 'path', 'href', 'url', 'method', 'value', 'code', 'event', 'state', 'status', 'variant', 'color', 'severity', 'size', 'placement', 'component', 'direction', 'align', 'justifyContent', 'alignItems', 'display', 'position', 'fontFamily', 'fontWeight', 'fontSize', 'inputTypes', 'outputTypes', 'chartType', 'target', 'rel', 'className', 'testId']);
const formatMethods = new Set(['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString', 'toFixed', 'toPrecision', 'toISOString']);
const technicalLiterals = new Set([
  ...JSON.parse(fs.readFileSync(path.join(frontend, 'localization/catalog-policy.json'), 'utf8')).technicalTokens,
  'ns', 'µs', 'ms', 's', 'min', 'h', 'd', 'B', 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB', 'bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'UTC', 'XML', 'JSONL',
]);

/** Match React's multiline JSX whitespace, including intentional single spaces. */
export function jsxText(text) {
  if (text.includes('&')) {
    const output = ts.transpileModule(`const element = <span>${text}</span>;`, { compilerOptions: { jsx: ts.JsxEmit.React, target: ts.ScriptTarget.ES2022 } }).outputText;
    const parsed = ts.createSourceFile('jsx.js', output, ts.ScriptTarget.Latest, true);
    const expression = parsed.statements[0]?.declarationList?.declarations[0]?.initializer;
    if (expression && ts.isCallExpression(expression) && ts.isStringLiteral(expression.arguments[2])) return expression.arguments[2].text;
  }
  const lines = text.split(/\r\n|\n|\r/);
  let last = -1;
  lines.forEach((line, index) => { if (/[^ \t]/.test(line)) last = index; });
  return lines.map((line, index) => {
    let value = line.replaceAll('\t', ' ');
    if (index !== 0) value = value.replace(/^ +/, '');
    if (index !== lines.length - 1) value = value.replace(/ +$/, '');
    return value + (value && index !== last ? ' ' : '');
  }).join('');
}

export function escapeICU(text) {
  return text.replaceAll("'", "''").replace(/[{}<]+/g, chars => `'${chars}'`);
}

function propertyName(node) {
  return node && (ts.isIdentifier(node) || ts.isStringLiteral(node)) ? node.text : '';
}

function ancestors(node) {
  const result = [];
  for (let parent = node.parent; parent; parent = parent.parent) result.push(parent);
  return result;
}

function componentOf(node) {
  for (const parent of ancestors(node)) {
    if (ts.isFunctionDeclaration(parent) && parent.name && /^[A-Z]/.test(parent.name.text)) return parent.name.text;
    if ((ts.isArrowFunction(parent) || ts.isFunctionExpression(parent)) && ts.isBlock(parent.body) && ts.isVariableDeclaration(parent.parent)
      && /^[A-Z]/.test(parent.parent.name.getText())) return parent.parent.name.getText();
  }
  return null;
}

function isInExpression(node, expression) {
  return expression && node.getStart() >= expression.getStart() && node.end <= expression.end;
}

function classify(node, sourceFile) {
  const parents = ancestors(node);
  const parent = node.parent;
  if (parents.some(item => ts.isImportDeclaration(item) || ts.isExportDeclaration(item)
    || ts.isImportTypeNode(item) || ts.isLiteralTypeNode(item))) return ['canonical', 'module-or-type'];
  if (parents.some(item => ts.isPropertyAssignment(item) && isInExpression(node, item.name))) return ['canonical', 'object-key'];
  if (ts.isElementAccessExpression(parent) && parent.argumentExpression === node) return ['review', 'indexed-key-or-label'];
  if (ts.isBinaryExpression(parent) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken,
    ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(parent.operatorToken.kind)) return ['canonical', 'comparison-discriminant'];
  const call = parents.find(ts.isCallExpression);
  if (call?.arguments[0] === node && /^(?:t|translate|message|richText|i18nText|i18nRichText|i18nMessage|i18nParameterMessage|i18nParameterText|finalCopyMessage|finalCopyText|streamMessage|__netcapT_*)$/.test(call.expression.getText(sourceFile))) return ['localized', 'message-call'];
  const attribute = parents.find(ts.isJsxAttribute);
  if (attribute) {
    const name = attribute.name.getText(sourceFile);
    if (name.startsWith('data-learn') || name.startsWith('aria-') && ['aria-label', 'aria-description', 'aria-roledescription', 'aria-valuetext'].includes(name)
      || displayNames.has(name)) return ['display', `jsx-attribute:${name}`];
    if (canonicalNames.has(name) || /^(?:data-|aria-|on[A-Z]|sx$|style$)/.test(name)) return ['canonical', `jsx-prop:${name}`];
  }
  if (ts.isJsxText(node)) return ['display', 'jsx-text'];
  if (call) {
    const callee = call.expression.getText(sourceFile);
    if (/^(?:console|logger|log)\./.test(callee)) return ['canonical', 'non-ui-log'];
    if (call.arguments[0] === node && (/^(?:t|translate|message|richText|i18nText|i18nRichText|i18nMessage|i18nParameterMessage|i18nParameterText|finalCopyMessage|finalCopyText|streamMessage|__netcapT_*)$/.test(callee) || /(?:^|\.)t$/.test(callee))) return ['localized', 'message-call'];
    if (/^(?:window\.)?(?:alert|confirm|prompt)$/.test(callee)) return ['display', 'dialog'];
    if (/^set(?:Error|Notice|Message|StatusText|Snackbar|Toast|Success)/.test(callee)) return ['display', 'stored-state-message'];
    if (/^(?:fetch|encodeURIComponent|decodeURIComponent)$/.test(callee) || /(?:^|\.)(?:getItem|setItem|removeItem|On|Emit|navigate|replace)$/.test(callee) || /^(?:router|history)\.push$/.test(callee)) return ['canonical', 'wire-or-storage-value'];
  }
  const assignment = parents.find(ts.isPropertyAssignment);
  if (assignment) {
    const name = propertyName(assignment.name);
    if (displayNames.has(name)) return ['display', `metadata:${name}`];
    if (canonicalNames.has(name)) return ['canonical', `metadata:${name}`];
  }
  if (parents.some(ts.isJsxExpression)) return ['display', 'jsx-expression'];
  if (parents.some(item => ts.isNewExpression(item) && item.expression.getText(sourceFile) === 'Error')) return ['review', 'error-may-reach-ui'];
  if (parents.some(item => ts.isTaggedTemplateExpression(item))) return ['review', 'tagged-template'];
  return ['review', 'callback-constant-or-data'];
}

function sourceMessage(node, sourceFile) {
  if (ts.isJsxText(node)) return { source: jsxText(sourceFile.text.slice(node.pos, node.end)), expressions: [] };
  if (ts.isStringLiteral(node) && ts.isJsxAttribute(node.parent) && node.text.includes('&')) {
    const output = ts.transpileModule(`const element = <span title=${node.getText(sourceFile)} />;`, { compilerOptions: { jsx: ts.JsxEmit.React, target: ts.ScriptTarget.ES2022 } }).outputText;
    const parsed = ts.createSourceFile('jsx.js', output, ts.ScriptTarget.Latest, true);
    const element = parsed.statements[0]?.declarationList?.declarations[0]?.initializer;
    const property = element?.arguments?.[1]?.properties?.[0];
    if (property && ts.isStringLiteral(property.initializer)) return { source: property.initializer.text, expressions: [] };
  }
  if (ts.isTemplateExpression(node)) {
    const expressions = node.templateSpans.map((span, index) => ({ name: `arg${index}`, expression: span.expression.getText(sourceFile) }));
    let source = escapeICU(node.head.text);
    node.templateSpans.forEach((span, index) => { source += `{arg${index}}` + escapeICU(span.literal.text); });
    return { source, expressions };
  }
  return { source: node.text, expressions: [] };
}

export function scanSource(text, file = 'fixture.tsx', repo = 'netcap') {
  const kind = file.endsWith('.json') ? ts.ScriptKind.JSON : file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, kind);
  if (sourceFile.parseDiagnostics.length) throw new Error(`Cannot parse ${file}: ${sourceFile.parseDiagnostics.map(item => ts.flattenDiagnosticMessageText(item.messageText, ' ')).join('; ')}`);
  const occurrences = [];
  const formatting = [];
  const dynamicUI = [];
  const displayBindings = [];
  const dynamicTranslations = [];
  const messageCoercions = [];
  const imported = sourceFile.statements.filter(ts.isImportDeclaration).filter(statement => /i18n/.test(statement.moduleSpecifier.getText(sourceFile)))
    .flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements : []);
  const deferredBindings = new Set(imported.filter(item => ['message', 'errorText', 'metadataMessage', 'joinMessages'].includes(item.propertyName?.text ?? item.name.text)).map(item => item.name.text));
  const renderedBindings = new Set(imported.filter(item => ['translate', 'richText', 'renderText', 'renderMessage', 'renderError', 'messageSource'].includes(item.propertyName?.text ?? item.name.text)).map(item => item.name.text));
  const seen = new Map();
  function visit(node) {
    if (ts.isCallExpression(node) && deferredBindings.has(node.expression.getText(sourceFile))) {
      for (const parent of ancestors(node)) {
        if (ts.isCallExpression(parent) && renderedBindings.has(parent.expression.getText(sourceFile))) break;
        if (ts.isTemplateExpression(parent) || ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.PlusToken
          || ts.isCallExpression(parent) && parent.expression.getText(sourceFile) === 'String') {
          messageCoercions.push({ line: sourceFile.getLineAndCharacterOfPosition(parent.getStart(sourceFile)).line + 1, expression: parent.getText(sourceFile), action: 'keep-descriptor-until-renderText-or-joinMessages' });
          break;
        }
        if (ts.isStatement(parent) || ts.isFunctionLike(parent)) break;
      }
    }
    if (ts.isJsxExpression(node) && node.expression && !ts.isStringLiteralLike(node.expression) && !ts.isTemplateExpression(node.expression)) {
      const attribute = ts.isJsxAttribute(node.parent) ? node.parent.name.getText(sourceFile) : null;
      if (attribute === null || displayNames.has(attribute) || attribute.startsWith('data-learn') || ['aria-label', 'aria-description', 'aria-valuetext'].includes(attribute)) {
        const expression = node.expression.getText(sourceFile);
        displayBindings.push({ line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1, attribute, expression, action: 'preserve-captured-data-or-localize-authored-metadata-at-render' });
      }
    }
    if (ts.isCallExpression(node)) {
      const expression = node.expression;
      if (/^(?:t|translate|i18nText|__netcapT_*)$/.test(expression.getText(sourceFile)) && node.arguments[0] && !ts.isStringLiteralLike(node.arguments[0])) {
        dynamicTranslations.push({ line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1, expression: node.getText(), action: 'review-app-owned-source-provenance' });
      }
      if (ts.isPropertyAccessExpression(expression) && (formatMethods.has(expression.name.text)
        || expression.expression.getText(sourceFile) === 'Intl')) {
        const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
        formatting.push({ start: node.getStart(sourceFile), end: node.end, line: position.line + 1, expression: node.getText(sourceFile), method: expression.name.text, action: 'review-explicit-unit-and-locale' });
      }
      if (/^set(?:Error|Notice|Message|Toast|Snackbar)/.test(expression.getText(sourceFile)) && node.arguments.some(arg => !ts.isStringLiteralLike(arg))) {
        dynamicUI.push({ line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1, expression: node.getText(), action: 'separate-app-message-from-untrusted-detail' });
      }
    }
    if (ts.isNewExpression(node) && node.expression.getText(sourceFile).startsWith('Intl.')) {
      formatting.push({ start: node.getStart(), end: node.end, line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1, expression: node.getText(), method: node.expression.getText(), action: 'review-explicit-unit-and-locale' });
    }
    if (ts.isStringLiteralLike(node) || ts.isJsxText(node) || ts.isTemplateExpression(node)) {
      // The enclosing template is one message, never independent text chunks.
      if (ts.isTemplateExpression(node.parent) || ts.isTemplateSpan(node.parent) && node.parent.literal === node) return;
      const { source, expressions } = sourceMessage(node, sourceFile);
      if (source.trim()) {
        let [classification, reason] = classify(node, sourceFile);
        if (['display', 'review'].includes(classification) && (!/[\p{L}]/u.test(source) || technicalLiterals.has(source.trim()))) {
          classification = 'canonical';
          reason = 'invariant-symbol-or-technical-token';
        }
        const syntax = ts.SyntaxKind[node.kind];
        const discriminator = `${syntax}\0${source}`;
        const ordinal = seen.get(discriminator) ?? 0;
        seen.set(discriminator, ordinal + 1);
        const start = node.getStart(sourceFile);
        const { line, character } = sourceFile.getLineAndCharacterOfPosition(start);
        const component = componentOf(node);
        const jsxParent = ancestors(node).find(item => ts.isJsxElement(item) || ts.isJsxFragment(item));
        const fragmented = ts.isJsxText(node) && jsxParent?.children.some(child => !ts.isJsxText(child));
        const safe = classification === 'display' && component && !fragmented
          && (['jsx-text', 'jsx-expression'].includes(reason) || reason.startsWith('jsx-attribute:') && ts.isJsxAttribute(node.parent)) && !expressions.length
          && !ancestors(node).some(item => ts.isCallExpression(item) || ts.isPropertyAssignment(item) || ts.isBinaryExpression(item) || ts.isConditionalExpression(item));
        const call = ancestors(node).find(ts.isCallExpression);
        occurrences.push({
          id: digest(`${repo}/${file}\0${discriminator}\0${ordinal}`).slice(0, 24),
          start, end: node.end, line: line + 1, column: character + 1, syntax, source,
          message: expressions.length ? source : escapeICU(source), key: stableKey(expressions.length ? source : escapeICU(source)),
          namespace: namespaceFor(file, source), classification, reason, component,
          messageReference: classification === 'localized' && call?.arguments[0] === node,
          migration: parentOwned(file) ? 'parent-owned' : safe ? 'safe-jsx' : 'review',
          fragmented: Boolean(fragmented), expressions,
        });
      }
      if (ts.isTemplateExpression(node)) {
        // Still inventory literals nested in interpolation expressions.
        node.templateSpans.forEach(span => visit(span.expression));
        return;
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return { occurrences, formatting, dynamicUI, displayBindings, dynamicTranslations, messageCoercions };
}

function filesUnder(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en')).flatMap(entry => {
    if (/^(?:__tests__|node_modules|dist|i18n)$/.test(entry.name)) return [];
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) return filesUnder(file);
    return /\.(?:tsx?|jsx?|json)$/.test(entry.name) && !/\.(?:test|spec|d)\.[jt]sx?$/.test(entry.name)
      && !/^i18n(?:\.|$)/.test(entry.name) ? [file] : [];
  });
}

export function inventory() {
  const files = [];
  for (const root of productionRoots) {
    for (const absolute of filesUnder(root.directory)) {
      const file = path.relative(roots[root.repo], absolute).split(path.sep).join('/');
      const text = fs.readFileSync(absolute, 'utf8');
      files.push({ repo: root.repo, file, sha256: digest(text), bytes: Buffer.byteLength(text), owner: parentOwned(file) ? 'parent' : 'source-migration', ...scanSource(text, file, root.repo) });
    }
  }
  for (const { repo, file: absolute } of htmlFiles) {
    const text = fs.readFileSync(absolute, 'utf8');
    files.push({ repo, file: path.relative(roots[repo], absolute).split(path.sep).join('/'), sha256: digest(text), bytes: Buffer.byteLength(text), owner: 'parent', occurrences: [], formatting: [], dynamicUI: [], displayBindings: [], dynamicTranslations: [], html: { action: 'parent-localizes-document-title-description-lang-dir', source: text } });
  }
  const byClassification = {};
  const byNamespace = {};
  for (const file of files) for (const occurrence of file.occurrences) {
    byClassification[occurrence.classification] = (byClassification[occurrence.classification] ?? 0) + 1;
    if (occurrence.classification === 'display') byNamespace[occurrence.namespace] = (byNamespace[occurrence.namespace] ?? 0) + 1;
  }
  return {
    schemaVersion: 1,
    scope: 'All authored production source under service src, shared netcap-ui/src, Pro src, and both index.html files; tests, generated Wails bindings, vendored chart JS and legal notices excluded.',
    summary: {
      files: files.length,
      filesByRepo: Object.fromEntries(Object.keys(roots).map(repo => [repo, files.filter(file => file.repo === repo).length])),
      authoredSourceBytes: files.reduce((sum, file) => sum + file.bytes, 0),
      byClassification, displayOccurrencesByNamespace: byNamespace,
      formattingSites: files.reduce((sum, file) => sum + file.formatting.length, 0),
      dynamicUISites: files.reduce((sum, file) => sum + file.dynamicUI.length, 0),
      displayBindings: files.reduce((sum, file) => sum + file.displayBindings.length, 0),
      dynamicTranslationSites: files.reduce((sum, file) => sum + file.dynamicTranslations.length, 0),
    },
    files,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const result = inventory();
  const index = process.argv.indexOf('--out');
  if (index !== -1) fs.writeFileSync(process.argv[index + 1], JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result.summary, null, 2));
}
