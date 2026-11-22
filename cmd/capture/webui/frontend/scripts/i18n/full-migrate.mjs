import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, productionRoots, roots, parentOwned, namespaceFor } from './config.mjs';
import { inventory, scanSource, digest, stableKey, escapeICU, jsxText } from './inventory.mjs';

const out = path.join(frontend, 'localization');
const baseline = '/var/folders/sb/n7njgj0s1ln8wkb4j9hs4n8h0000gn/T/opencode/netcap-i18n-source-baseline.json';
const snapshot = inventory();
const baselineSources = process.argv.includes('--from-baseline') ? new Map(JSON.parse(fs.readFileSync(baseline, 'utf8')).map(file => [`${file.repo}/${file.file}`, file.text])) : null;
const catalog = {};
const report = [];
const parentMessages = [];
const rawSources = [];
const excludedFiles = /\/(?:appearance|graphAppearance|theme|graphLayout|replay|timelineTime|bpfSyntaxHighlight|filterSyntaxHighlight|regexSyntaxHighlight|html|recordUnits)\.ts$/;
const displayProperties = new Set(['label', 'title', 'description', 'helperText', 'placeholder', 'alt', 'summary', 'primary', 'secondary', 'question', 'caption', 'tooltip', 'emptyText', 'noOptionsText', 'loadingText', 'headerName', 'displayName', 'text', 'message', 'msg']);
const statePattern = /(?:error|notice|message|success|toast|snackbar|notification|buttonText|failure|statusText)$/i;
const inlineTags = new Set(['strong', 'b', 'em', 'i', 'code', 'span', 'a', 'kbd', 'small', 'Link']);
const invariant = new Set([...JSON.parse(fs.readFileSync(path.join(out, 'catalog-policy.json'), 'utf8')).technicalTokens, 'UTC', 'ns', 'µs', 'ms', 's', 'min', 'h', 'd', 'B', 'KB', 'MB', 'GB', 'TB', 'KiB', 'MiB', 'GiB', 'TiB', 'bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s', 'HTTP/2', 'HTTP/3', 'TLS 1.2', 'TLS 1.3', 'C2', 'ASN', 'IP', 'IP/CIDR', 'IPv4/IPv6', 'YAML', 'XML', 'HTML', 'EXIF', 'OS', 'MD5', 'SHA1', 'SHA256', 'SHA-256', 'URL', 'SNI', 'ALPN', 'TTL', 'RTT', 'CPU', 'RAM', 'PID', 'MAC/IP', 'LLDP', 'CDP', 'DHCP', 'NTP', 'RDP', 'FTP', 'IMAP', 'POP3', 'SMTP', 'SIP', 'ICMP', 'ICMPv6', 'ARP', 'MIME', 'JA3', 'JA3S', 'STUN', 'VXLAN', 'GRE', 'GTP', 'MPLS', 'DGA', 'CIDR', 'CID', 'CISA KEV', 'CVSS v3', 'CVSS v2', 'EPS S', 'MITRE ATT&CK']);
const linguistic = source => /\p{L}/u.test(source) && !invariant.has(source.trim())
  && !source.trim().split(/[\s/|(),:+]+/).every(part => invariant.has(part) || /^[\d.−–—-]+$/.test(part))
  && !/^(?:[\d.\s+−%×/():–—-]+|CVE-\d{4}-\d+|v?\d+(?:\.\d+)+)$/i.test(source.trim());
const nameOf = node => node && (ts.isIdentifier(node) || ts.isStringLiteral(node)) ? node.text : '';
const parents = node => { const result = []; for (let p = node.parent; p; p = p.parent) result.push(p); return result; };

function addMessage(file, source, message, node, context = '') {
  if (!linguistic(source) && !/[{}]/.test(message)) return null;
  const namespace = namespaceFor(file.file, source);
  const key = stableKey(message, context);
  const qualified = `${namespace}:${key}`;
  catalog[qualified] ??= { namespace, key, message, context, locations: [] };
  catalog[qualified].locations.push({ repo: file.repo, file: file.file, offset: node.getStart(), line: node.getSourceFile().getLineAndCharacterOfPosition(node.getStart()).line + 1, source });
  return qualified;
}

function migrate(file, text) {
  const sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const imports = new Set();
  const edits = [];
  const covered = [];
  const localizedPositions = [];
  const states = new Map();
  const metadata = new Map();
  const declarations = new Map();
  const catalogedStatic = new Set();
  const originalOccurrences = new Map(file.occurrences.map(item => [item.start, item]));
  const changes = [];
  const uses = name => { imports.add(name); return ({ translate: 'i18nText', message: 'i18nMessage', renderText: 'i18nRenderText', richText: 'i18nRichText', useLocale: 'useUILocale', getLocale: 'getUILocale', MessageText: 'UIMessageText', formatNumber: 'i18nNumber', renderUIMessage: 'i18nBackendText' })[name] ?? name; };
  const inside = (start, end) => covered.some(([a, b]) => start >= a && end <= b);
  function edit(node, replacement, reason, start = node.getStart(sf), end = node.end) {
    if (inside(start, end)) return false;
    edits.push({ start, end, replacement }); covered.push([start, end]); localizedPositions.push(start);
    changes.push({ line: sf.getLineAndCharacterOfPosition(start).line + 1, reason, before: text.slice(start, end), after: replacement });
    return true;
  }
  function collect(node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) declarations.set(node.name.text, node);
    if (ts.isVariableDeclaration(node) && ts.isArrayBindingPattern(node.name) && node.initializer && ts.isCallExpression(node.initializer) && /^(?:React\.)?useState$/.test(node.initializer.expression.getText(sf))) {
      const [value, setter] = node.name.elements;
      const valueName = value?.name?.getText(sf), setterName = setter?.name?.getText(sf);
      const type = node.initializer.typeArguments?.[0];
      const initial = node.initializer.arguments[0];
      const objectText = type?.getText(sf) ?? '';
      const messageObject = /\b(?:message|msg|text)\s*:\s*string\b/.test(objectText);
      const stringState = type ? /\bstring\b/.test(objectText) && !objectText.includes('{') : initial && ts.isStringLiteralLike(initial);
      if (valueName && setterName && (statePattern.test(valueName) && stringState || messageObject)) {
        states.set(valueName, { node, setter: setterName, object: objectText.includes('{'), initial, type });
      }
    }
    ts.forEachChild(node, collect);
  }
  collect(sf);

  function staticOrigin(node, seen = new Set()) {
    if (!node || seen.has(node)) return false;
    seen.add(node);
    if (ts.isArrayLiteralExpression(node) || ts.isObjectLiteralExpression(node)) return true;
    if (ts.isAsExpression(node) || ts.isParenthesizedExpression(node)) return staticOrigin(node.expression, seen);
    if (ts.isIdentifier(node)) {
      const declaration = declarations.get(node.text);
      if (declaration?.initializer && staticOrigin(declaration.initializer, seen)) return true;
      for (const p of parents(node)) {
        if (ts.isArrowFunction(p) && p.parameters.some(param => param.name.getText(sf).split(/[^A-Za-z0-9_$]+/).includes(node.text))) {
          const call = p.parent;
          if (ts.isCallExpression(call) && ts.isPropertyAccessExpression(call.expression)) return staticOrigin(call.expression.expression, seen);
        }
      }
      return false;
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) return staticOrigin(node.expression, seen);
    if (ts.isCallExpression(node)) {
      if (ts.isPropertyAccessExpression(node.expression)) {
        if (node.expression.expression.getText(sf) === 'Object') return staticOrigin(node.arguments[0], seen);
        if (['filter', 'map', 'flatMap', 'slice', 'sort', 'find', 'concat', 'reduce'].includes(node.expression.name.text)) return staticOrigin(node.expression.expression, seen);
      }
    }
    return false;
  }
  function uiState(node) {
    if (ts.isIdentifier(node)) return states.has(node.text);
    if (ts.isPropertyAccessExpression(node) && node.expression.getText(sf) === 'live' && node.name.text === 'error') return true;
    return ts.isPropertyAccessExpression(node) && states.has(node.expression.getText(sf)) && /^(?:message|msg|text)$/.test(node.name.text);
  }
  function originValues(node, seen = new Set()) {
    if (!node || seen.has(node)) return [];
    seen.add(node);
    if (ts.isAsExpression(node) || ts.isParenthesizedExpression(node)) return originValues(node.expression, seen);
    if (ts.isIdentifier(node)) {
      for (const p of parents(node)) if (ts.isArrowFunction(p) && ts.isCallExpression(p.parent) && ts.isPropertyAccessExpression(p.parent.expression)) {
        const parameter = p.parameters.find(parameter => parameter.name.getText(sf).split(/[^A-Za-z0-9_$]+/).includes(node.text));
        if (!parameter) continue;
        const rows = originValues(p.parent.expression.expression, seen);
        if (ts.isArrayBindingPattern(parameter.name)) {
          const index = parameter.name.elements.findIndex(element => element.name?.getText(sf) === node.text);
          return rows.flatMap(row => ts.isArrayLiteralExpression(row) && row.elements[index] ? [row.elements[index]] : []);
        }
        return rows;
      }
      return originValues(declarations.get(node.text)?.initializer, seen);
    }
    if (ts.isArrayLiteralExpression(node)) return node.elements.flatMap(element => ts.isSpreadElement(element) ? originValues(element.expression, seen) : [element]);
    if (ts.isObjectLiteralExpression(node) || ts.isStringLiteralLike(node)) return [node];
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && ['filter', 'map', 'flatMap', 'slice', 'sort', 'find', 'concat'].includes(node.expression.name.text)) return originValues(node.expression.expression, seen);
    if (ts.isPropertyAccessExpression(node)) return originValues(node.expression, seen).flatMap(value => ts.isObjectLiteralExpression(value) ? value.properties.filter(property => ts.isPropertyAssignment(property) && nameOf(property.name) === node.name.text).map(property => property.initializer) : []);
    return [];
  }
  function ownedString(node) {
    return ts.isStringLiteralLike(node) || ts.isConditionalExpression(node) && ownedString(node.whenTrue) && ownedString(node.whenFalse);
  }
  function displayOrigin(node) {
    if (!ts.isIdentifier(node) && !ts.isPropertyAccessExpression(node) && !ts.isElementAccessExpression(node)) return false;
    const values = originValues(node);
    if (values.length && values.every(ownedString)) return true;
    if (ts.isElementAccessExpression(node)) {
      const objects = originValues(node.expression);
      return objects.length > 0 && objects.every(value => ts.isObjectLiteralExpression(value) && value.properties.every(property => ts.isPropertyAssignment(property) && ownedString(property.initializer)));
    }
    return false;
  }
  function catalogStatic(node, seen = new Set()) {
    if (!node || seen.has(node)) return;
    seen.add(node);
    if (ts.isIdentifier(node)) {
      const declaration = declarations.get(node.text);
      if (declaration && !/(?:color|style|palette|icon|route|path|_sx)$/i.test(node.text)) catalogStatic(declaration.initializer, seen);
      for (const p of parents(node)) if (ts.isArrowFunction(p) && p.parameters.some(parameter => parameter.name.getText(sf).split(/[^A-Za-z0-9_$]+/).includes(node.text)) && ts.isCallExpression(p.parent) && ts.isPropertyAccessExpression(p.parent.expression)) catalogStatic(p.parent.expression.expression, seen);
      return;
    }
    if (ts.isAsExpression(node) || ts.isParenthesizedExpression(node) || ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) { catalogStatic(node.expression, seen); return; }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) { catalogStatic(node.expression.expression.getText(sf) === 'Object' ? node.arguments[0] : node.expression.expression, seen); return; }
    if (ts.isArrayLiteralExpression(node)) { node.elements.forEach(element => catalogStatic(element, seen)); return; }
    if (ts.isObjectLiteralExpression(node)) {
      for (const property of node.properties) if (ts.isPropertyAssignment(property) && !['id', 'key', 'path', 'href', 'url', 'type', 'value', 'field', 'chartType', 'inputTypes', 'outputTypes', 'color', 'icon', 'style', 'sx'].includes(nameOf(property.name))) catalogStatic(property.initializer, seen);
      return;
    }
    if (ts.isStringLiteralLike(node) && linguistic(node.text) && !cssContext(node) && !catalogedStatic.has(node.getStart(sf))) {
      addMessage(file, node.text, escapeICU(node.text), node, 'app-authored display metadata'); catalogedStatic.add(node.getStart(sf));
    }
  }
  function cssContext(node) {
    const chain = parents(node);
    return chain.some(p => ts.isJsxAttribute(p) && ['sx', 'style'].includes(p.name.getText(sf)))
      || chain.some(p => ts.isVariableDeclaration(p) && /(?:_SX|_STYLE|Style|Styles|Palette|COLORS|PALETTE|SHADER|Shader)$/.test(p.name.getText(sf)))
      || chain.some(p => ts.isPropertyAssignment(p) && ['style', 'sx', 'vertexShader', 'fragmentShader', 'uniforms', 'selector'].includes(nameOf(p.name)))
      || /^data\([^)]+\)$/.test(node.text ?? '');
  }
  function wireContext(node) {
    return parents(node).some(p => ts.isCallExpression(p) && /(?:^|\.)(?:fetch|encodeURIComponent|decodeURIComponent|join|split|replace|replaceAll|match|test|getItem|setItem|removeItem|On|Emit|addEventListener|removeEventListener|navigate|push|send|setHeader|setAttribute|querySelector|querySelectorAll|startsWith|endsWith|includes|indexOf)$/.test(p.expression.getText(sf)))
      || parents(node).some(p => ts.isCaseClause(p))
      || parents(node).some(p => ts.isBinaryExpression(p) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(p.operatorToken.kind) && (p.left === node || p.right === node));
  }
  function textSource(node) {
    if (ts.isJsxText(node) && process.argv.includes('--legacy-jsx-whitespace')) return jsxText(node.getText(sf));
    if (ts.isJsxText(node) && process.argv.includes('--jsx-whitespace')) return jsxText(text.slice(node.pos, node.end));
    return originalOccurrences.get(node.getStart(sf))?.source ?? (ts.isJsxText(node) ? jsxText(node.getText(sf)) : node.text ?? '');
  }
  function isInline(node) {
    if (!ts.isJsxElement(node)) return false;
    const name = node.openingElement.tagName.getText(sf);
    return inlineTags.has(name) || ['Typography', 'Box'].includes(name) && node.openingElement.attributes.properties.some(attr => ts.isJsxAttribute(attr) && attr.name.getText(sf) === 'component' && attr.initializer?.getText(sf) === '"span"');
  }

  function messageParts(children) {
    const values = [];
    const richValues = [];
    let raw = '', pattern = '', literals = '';
    function expression(node) {
      const name = `arg${values.length}`;
      values.push({ name, node });
      raw += `{${name}}`; return `{${name}}`;
    }
    function child(node) {
      if (Object.hasOwn(node, '_literal')) { raw += node._literal; literals += node._literal; return escapeICU(node._literal); }
      if (ts.isJsxText(node)) { const source = textSource(node); raw += source; literals += source; return escapeICU(source); }
      if (ts.isJsxExpression(node)) {
        if (!node.expression) return '';
        if (ts.isStringLiteralLike(node.expression)) { const source = node.expression.text; raw += source; literals += source; return escapeICU(source); }
        return expression(node.expression);
      }
      if (isInline(node)) {
        const name = `tag${richValues.length}`;
        richValues.push({ name, node });
        return `<${name}>${node.children.map(child).join('')}</${name}>`;
      }
      return expression(node);
    }
    pattern = children.map(child).join('');
    if (!linguistic(literals)) return null;
    // English suffix conditionals become one ICU plural message, not translated suffixes.
    for (const value of values) {
      const condition = ts.isConditionalExpression(value.node) ? value.node : null;
      if (!condition || !ts.isBinaryExpression(condition.condition) || !ts.isStringLiteralLike(condition.whenTrue) || !ts.isStringLiteralLike(condition.whenFalse)) continue;
      const op = condition.condition.operatorToken.kind;
      const isEqual = [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken].includes(op);
      const isUnequal = [ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsToken].includes(op);
      if ((!isEqual && !isUnequal) || !['1', "'1'", '"1"'].includes(condition.condition.right.getText(sf))) continue;
      const suffixes = [condition.whenTrue.text, condition.whenFalse.text];
      if (!suffixes.every(item => item === '' || item === 's')) continue;
      const countNode = ts.isCallExpression(condition.condition.left) && condition.condition.left.expression.getText(sf) === 'String' ? condition.condition.left.arguments[0] : condition.condition.left;
      const countExpression = countNode.getText(sf);
      const count = values.find(item => item.node.getText(sf).replace(/\.toLocaleString\([^)]*\)$/, '') === countExpression);
      if (!count) continue;
      count.node = countNode;
      const singular = isEqual ? condition.whenTrue.text : condition.whenFalse.text;
      const plural = isEqual ? condition.whenFalse.text : condition.whenTrue.text;
      const branch = suffix => pattern.replace(`{${value.name}}`, escapeICU(suffix)).replaceAll(`{${count.name}}`, '#');
      pattern = `{${count.name}, plural, one {${branch(singular)}} other {${branch(plural)}}}`;
      values.splice(values.indexOf(value), 1);
      break;
    }
    return { raw, pattern, values, richValues };
  }

  function translated(node, deferred = false) {
    if (ts.isStringLiteralLike(node)) {
      const source = textSource(node);
      if (!linguistic(source)) return node.getText(sf);
      const key = addMessage(file, source, escapeICU(source), node);
      return `${uses(deferred ? 'message' : 'translate')}(${JSON.stringify(key)})`;
    }
    if (ts.isTemplateExpression(node)) {
      const part = messageParts([{ _literal: node.head.text }, ...node.templateSpans.flatMap(span => [{ kind: ts.SyntaxKind.JsxExpression, expression: span.expression }, { _literal: span.literal.text }])]);
      if (!part) return node.getText(sf);
      const key = addMessage(file, part.raw, part.pattern, node);
      return `${uses(deferred ? 'message' : 'translate')}(${JSON.stringify(key)}, { ${part.values.map(value => `${value.name}: ${emit(value.node)}`).join(', ')} })`;
    }
    return emit(node);
  }

  function emit(node) {
    if (inside(node.getStart(sf), node.end)) {
      const existing = edits.find(edit => edit.start === node.getStart(sf) && edit.end === node.end);
      if (existing) return existing.replacement;
    }
    if (ts.isStringLiteralLike(node) || ts.isTemplateExpression(node)) return translated(node);
    if (ts.isConditionalExpression(node)) return `${emitRaw(node.condition)} ? ${emit(node.whenTrue)} : ${emit(node.whenFalse)}`;
    if (ts.isBinaryExpression(node) && [ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.AmpersandAmpersandToken].includes(node.operatorToken.kind)) return `${emit(node.left)} ${node.operatorToken.getText(sf)} ${emit(node.right)}`;
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) || ts.isJsxFragment(node)) return renderJSX(node);
    if (uiState(node)) return `${uses('renderText')}(${node.getText(sf)})`;
    if (displayOrigin(node)) {
      catalogStatic(node); return `${uses('translate')}(${node.getText(sf)})`;
    }
    return emitRaw(node);
  }
  function emitRaw(node) {
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) || ts.isJsxFragment(node)) return renderJSX(node);
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text;
      if (['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString'].includes(method)) {
        const args = node.arguments.slice(1).map(arg => arg.getText(sf));
        return `${node.expression.getText(sf)}(${uses('getLocale')}()${args.length ? ', ' + args.join(', ') : ''})`;
      }
      if (method === 'toFixed') {
        const digits = node.arguments[0]?.getText(sf) ?? '0';
        return `${uses('formatNumber')}(${node.expression.expression.getText(sf)}, { minimumFractionDigits: ${digits}, maximumFractionDigits: ${digits}, useGrouping: false })`;
      }
    }
    let output = node.getText(sf);
    const nested = [];
    function visit(child) {
      if (ts.isPropertyAccessExpression(child) && uiState(child.expression) && ['includes', 'startsWith', 'endsWith', 'length', 'toLowerCase'].includes(child.name.text)) {
        imports.add('messageSource');
        nested.push({ start: child.expression.getStart(sf) - node.getStart(sf), end: child.expression.end - node.getStart(sf), text: `messageSource(${child.expression.getText(sf)})` }); return;
      }
      if (ts.isCallExpression(child) && [...states.values()].some(state => state.setter === child.expression.getText(sf)) && child.arguments[0]) {
        const argument = child.arguments[0];
        nested.push({ start: argument.getStart(sf) - node.getStart(sf), end: argument.end - node.getStart(sf), text: deferred(argument) }); return;
      }
      if (child !== node && (ts.isJsxElement(child) || ts.isJsxSelfClosingElement(child) || ts.isJsxFragment(child))) { nested.push({ start: child.getStart(sf) - node.getStart(sf), end: child.end - node.getStart(sf), text: renderJSX(child) }); return; }
      if (child !== node && ts.isCallExpression(child) && ts.isPropertyAccessExpression(child.expression) && ['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString', 'toFixed'].includes(child.expression.name.text)) {
        nested.push({ start: child.getStart(sf) - node.getStart(sf), end: child.end - node.getStart(sf), text: emitRaw(child) }); return;
      }
      if (child !== node && (ts.isStringLiteralLike(child) || ts.isTemplateExpression(child))) {
        const occurrence = originalOccurrences.get(child.getStart(sf));
        if (occurrence?.classification === 'display' && !cssContext(child) && !wireContext(child) && occurrence.reason !== 'object-key') {
          if (ts.isArrayLiteralExpression(child.parent)) {
            addMessage(file, textSource(child), escapeICU(textSource(child)), child, 'app-authored display metadata'); return;
          }
          const attribute = parents(child).find(ts.isJsxAttribute);
          if (attribute && !displayProperties.has(attribute.name.getText(sf)) && attribute.name.getText(sf) !== 'data-learn' && !attribute.name.getText(sf).startsWith('aria-')) return;
          const call = parents(child).find(ts.isCallExpression);
          if (call && !/^(?:window\.)?(?:confirm|alert|prompt)$/.test(call.expression.getText(sf))) return;
          if (ts.isAsExpression(child.parent)) return;
          nested.push({ start: child.getStart(sf) - node.getStart(sf), end: child.end - node.getStart(sf), text: translated(child) }); return;
        }
      }
      ts.forEachChild(child, visit);
    }
    ts.forEachChild(node, visit);
    for (const item of nested.sort((a, b) => b.start - a.start)) output = output.slice(0, item.start) + item.text + output.slice(item.end);
    return output;
  }
  function deferred(value) {
    if (ts.isStringLiteralLike(value) || ts.isTemplateExpression(value)) return translated(value, true);
    if (ts.isConditionalExpression(value)) return `${value.condition.getText(sf)} ? ${deferred(value.whenTrue)} : ${deferred(value.whenFalse)}`;
    if (ts.isBinaryExpression(value) && [ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(value.operatorToken.kind)) return `${value.left.getText(sf)} ${value.operatorToken.getText(sf)} ${deferred(value.right)}`;
    if (ts.isObjectLiteralExpression(value)) {
      const parts = value.properties.map(property => ts.isPropertyAssignment(property) && ['message', 'msg', 'text'].includes(nameOf(property.name)) ? `${property.name.getText(sf)}: ${deferred(property.initializer)}` : property.getText(sf));
      return `{ ${parts.join(', ')} }`;
    }
    return value.getText(sf);
  }
  function renderAttributes(attributes) {
    let output = attributes.getText(sf);
    const replacements = [];
    for (const attribute of attributes.properties) {
      if (!ts.isJsxAttribute(attribute) || !attribute.initializer) continue;
      const name = attribute.name.getText(sf);
      const display = displayProperties.has(name) || name === 'data-learn' || ['aria-label', 'aria-description', 'aria-roledescription', 'aria-valuetext'].includes(name);
      let replacement;
      if (display && ts.isStringLiteral(attribute.initializer)) replacement = `{${translated(attribute.initializer)}}`;
      else if (ts.isJsxExpression(attribute.initializer) && attribute.initializer.expression) {
        replacement = `{${display ? emit(attribute.initializer.expression) : emitRaw(attribute.initializer.expression)}}`;
      }
      if (replacement) replacements.push({ start: attribute.initializer.getStart(sf) - attributes.getStart(sf), end: attribute.initializer.end - attributes.getStart(sf), text: replacement });
    }
    for (const item of replacements.sort((a, b) => b.start - a.start)) output = output.slice(0, item.start) + item.text + output.slice(item.end);
    return output;
  }
  function renderChildren(children) {
    const chunks = [];
    let group = [];
    function flush() {
      if (!group.length) return;
      const part = messageParts(group);
      if (!part) chunks.push(group.map(node => ts.isJsxExpression(node) && node.expression ? `{${emit(node.expression)}}` : isInline(node) ? renderJSX(node) : node.getText(sf)).join(''));
      else {
        const key = addMessage(file, part.raw, part.pattern, group[0]);
        const values = part.values.map(value => `${value.name}: ${emit(value.node)}`);
        for (const tag of part.richValues) {
          const name = tag.node.openingElement.tagName.getText(sf);
          const attrs = renderAttributes(tag.node.openingElement.attributes);
          values.push(`${tag.name}: (chunks: import('react').ReactNode[]) => <${name}${attrs ? ' ' + attrs : ''}>{chunks}</${name}>`);
        }
        const firstText = ts.isJsxText(group[0]) ? text.slice(group[0].pos, group[0].end) : '';
        const lastText = ts.isJsxText(group.at(-1)) ? text.slice(group.at(-1).pos, group.at(-1).end) : '';
        const prefix = firstText.match(/^\s*\n[ \t]*/)?.[0] ?? '';
        const suffix = lastText.match(/\n[ \t]*$/)?.[0] ?? '';
        chunks.push(`${prefix}{${uses(values.length ? 'richText' : 'translate')}(${JSON.stringify(key)}${values.length ? ', { ' + values.join(', ') + ' }' : ''})}${suffix}`);
      }
      group = [];
    }
    for (const child of children) {
      if (ts.isJsxText(child) || ts.isJsxExpression(child) || isInline(child)) group.push(child);
      else { flush(); chunks.push(renderJSX(child)); }
    }
    flush(); return chunks.join('');
  }
  function renderJSX(node) {
    if (ts.isJsxFragment(node)) return `<>${renderChildren(node.children)}</>`;
    if (ts.isJsxSelfClosingElement(node)) {
      const name = node.tagName.getText(sf), attrs = renderAttributes(node.attributes);
      return `<${name}${attrs ? ' ' + attrs : ''} />`;
    }
    if (!ts.isJsxElement(node)) return emitRaw(node);
    const name = node.openingElement.tagName.getText(sf), attrs = renderAttributes(node.openingElement.attributes);
    return `<${name}${attrs ? ' ' + attrs : ''}>${renderChildren(node.children)}</${name}>`;
  }

  function visit(node) {
    if (inside(node.getStart(sf), node.end)) return;
    if (ts.isJsxElement(node) || ts.isJsxFragment(node) || ts.isJsxSelfClosingElement(node)) {
      edit(node, renderJSX(node), 'source-level-jsx-message-and-display-bindings'); return;
    }
    if (ts.isCallExpression(node) && states.size) {
      const state = [...states.values()].find(state => state.setter === node.expression.getText(sf));
      if (state && node.arguments[0]) {
        const argument = node.arguments[0];
        edit(argument, deferred(argument), 'deferred-state-message'); return;
      }
    }
    if (ts.isPropertyAccessExpression(node) && uiState(node.expression) && ['includes', 'startsWith', 'endsWith', 'length', 'toLowerCase'].includes(node.name.text)) {
      imports.add('messageSource');
      edit(node.expression, `messageSource(${node.expression.getText(sf)})`, 'locale-independent-message-logic'); return;
    }
    if ((ts.isStringLiteralLike(node) || ts.isTemplateExpression(node)) && linguistic(textSource(node))) {
      const occurrence = originalOccurrences.get(node.getStart(sf));
      if (occurrence?.classification === 'canonical' || cssContext(node) || wireContext(node) || ts.isAsExpression(node.parent)) return;
      const property = ts.isPropertyAssignment(node.parent) ? nameOf(node.parent.name) : '';
      if (displayProperties.has(property) || ['name', 'category'].includes(property) && staticOrigin(node.parent.parent)) {
        addMessage(file, textSource(node), escapeICU(textSource(node)), node, 'app-authored display metadata');
        metadata.set(node.getStart(sf), 'Static metadata retains canonical identity and is translated at its display binding.');
        return;
      }
      const statement = parents(node).find(ts.isReturnStatement);
      const fn = parents(node).find(parent => ts.isFunctionDeclaration(parent) || ts.isArrowFunction(parent) || ts.isFunctionExpression(parent));
      const name = fn && ts.isFunctionDeclaration(fn) ? fn.name?.text ?? '' : fn?.parent && ts.isVariableDeclaration(fn.parent) ? fn.parent.name.getText(sf) : '';
      if (statement && /(?:label|describe|format|title|status|message|error|friendly|summary|explain|reason|hint|badge|tooltip)/i.test(name) && !/color|key|path|url|id|csv|json|html|hash/i.test(name)) {
        edit(node, translated(node), 'display-helper-return'); return;
      }
      if (occurrence?.reason === 'dialog') { edit(node, translated(node), 'native-dialog'); return; }
      if (occurrence?.classification === 'display' && occurrence.reason === 'stored-state-message' && states.size && parents(node).some(parent => ts.isCallExpression(parent) && [...states.values()].some(state => state.setter === parent.expression.getText(sf)))) { edit(node, translated(node), 'callback-display-message'); return; }
    }
    ts.forEachChild(node, visit);
  }
  if (!excludedFiles.test(file.file)) visit(sf);

  // State descriptors preserve the current locale when a toast remains open.
  for (const state of states.values()) {
    if (!state.object) {
      if (state.type && /\bstring\b/.test(state.type.getText(sf))) edit(state.type, state.type.getText(sf).replace(/\bstring\b/g, uses('MessageText')), 'deferred-state-type');
      else if (!state.type && state.initial && ts.isStringLiteralLike(state.initial)) {
        const call = state.node.initializer;
        edits.push({ start: call.expression.end, end: call.expression.end, replacement: `<${uses('MessageText')}>` });
      }
      if (state.initial && ts.isStringLiteralLike(state.initial) && linguistic(state.initial.text)) edit(state.initial, translated(state.initial, true), 'deferred-state-initial-value');
    } else if (state.type) {
      edit(state.type, state.type.getText(sf).replace(/\b((?:message|msg|text)\s*:\s*)string\b/g, `$1${uses('MessageText')}`), 'deferred-message-property-type');
    }
  }
  // Catalog module metadata without changing its values, IDs, object keys or order.
  for (const occurrence of file.occurrences) {
    if (occurrence.classification !== 'display' || inside(occurrence.start, occurrence.end) || !linguistic(occurrence.source)) continue;
    if (occurrence.reason.startsWith('metadata:') && !excludedFiles.test(file.file)) {
      const node = findNode(sf, occurrence.start, occurrence.end);
      if (node && !cssContext(node) && !wireContext(node)) addMessage(file, occurrence.source, occurrence.message, node, 'app-authored display metadata');
    }
  }
  if (!edits.length && !imports.size) return { text, changes, metadata: [...metadata] };
  const components = [];
  function componentsIn(node) {
    if ((ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && node.body && ts.isBlock(node.body)) {
      const name = node.name?.text ?? (ts.isVariableDeclaration(node.parent) ? node.parent.name.getText(sf) : '');
      let jsx = false;
      const check = child => { if (ts.isJsxElement(child) || ts.isJsxFragment(child) || ts.isJsxSelfClosingElement(child)) jsx = true; else ts.forEachChild(child, check); };
      ts.forEachChild(node.body, check);
      if (jsx && /^[A-Z]/.test(name)) components.push(node);
    }
    ts.forEachChild(node, componentsIn);
  }
  componentsIn(sf);
  for (const component of components) {
    if (inside(component.body.getStart(sf) + 1, component.body.getStart(sf) + 1)) continue;
    edits.push({ start: component.body.getStart(sf) + 1, end: component.body.getStart(sf) + 1, replacement: `\n  const __uiLocale = ${uses('useLocale')}();` });
  }
  // Invalidate translated memoized views while leaving state and canonical keys intact.
  function memoDependencies(node) {
    if (ts.isCallExpression(node) && /^(?:React\.)?use(?:Memo|Callback)$/.test(node.expression.getText(sf)) && node.arguments[1] && ts.isArrayLiteralExpression(node.arguments[1]) && components.some(component => node.getStart() > component.body.getStart() && node.end < component.body.end)) {
      const callback = node.arguments[0];
      if (localizedPositions.some(position => position >= callback.getStart() && position <= callback.end)) {
        const array = node.arguments[1];
        if (!inside(array.getStart(), array.end)) edits.push({ start: array.end - 1, end: array.end - 1, replacement: `${array.elements.length ? ', ' : ''}__uiLocale` });
      }
    }
    ts.forEachChild(node, memoDependencies);
  }
  memoDependencies(sf);
  if (imports.size) {
    const importNodes = sf.statements.filter(ts.isImportDeclaration);
    const start = importNodes.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    let module = file.repo === 'netcap-pro' ? path.posix.relative(path.posix.dirname(file.file), 'frontend/src/lib/i18n') : path.posix.relative(path.posix.dirname(file.file), 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n');
    if (!module.startsWith('.')) module = './' + module;
    const names = [...imports].map(name => `${name === 'MessageText' ? 'type ' : ''}${name}${uses(name) === name ? '' : ' as ' + uses(name)}`);
    edits.push({ start, end: start, replacement: `\nimport { ${names.join(', ')} } from ${JSON.stringify(module)};\n` });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start || b.end - a.end)) {
    if (edit.end > boundary) throw new Error(`Overlapping source edits ${file.file}:${edit.start}`);
    output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start;
  }
  const parsed = ts.createSourceFile(file.file, output, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  if (parsed.parseDiagnostics.length) {
    fs.writeFileSync('/var/folders/sb/n7njgj0s1ln8wkb4j9hs4n8h0000gn/T/opencode/netcap-i18n-failed.tsx', output);
    throw new Error(`Invalid migrated syntax ${file.file}: ${parsed.parseDiagnostics.map(item => `${parsed.getLineAndCharacterOfPosition(item.start).line + 1}: ${ts.flattenDiagnosticMessageText(item.messageText, ' ')}`).join('; ')}`);
  }
  return { text: output, changes, metadata: [...metadata] };
}

function findNode(sf, start, end) {
  let found;
  function visit(node) { if (node.getStart(sf) === start && node.end === end) found = node; if (!found && node.pos <= start && node.end >= end) ts.forEachChild(node, visit); }
  visit(sf); return found;
}

const changes = [];
for (const file of snapshot.files) {
  const absolute = path.join(roots[file.repo], file.file);
  const text = baselineSources?.get(`${file.repo}/${file.file}`) ?? fs.readFileSync(absolute, 'utf8');
  if (baselineSources?.has(`${file.repo}/${file.file}`)) Object.assign(file, { sha256: digest(text), ...scanSource(text, file.file, file.repo) });
  if (file.html || parentOwned(file.file) || /\/(?:preferences|Preferences|PresentationControls|AppearanceControls)/.test(file.file)) {
    for (const occurrence of file.occurrences) if (occurrence.classification === 'display' && linguistic(occurrence.source)) {
      const key = addMessage(file, occurrence.source, occurrence.message, { getSourceFile: () => ({ getLineAndCharacterOfPosition: () => ({ line: occurrence.line - 1 }) }), getStart: () => occurrence.start });
      parentMessages.push({ repo: file.repo, file: file.file, line: occurrence.line, key, source: occurrence.source, params: occurrence.expressions });
    }
    continue;
  }
  if (file.file.endsWith('.json')) {
    for (const occurrence of file.occurrences) if (occurrence.classification === 'display' && linguistic(occurrence.source)) {
      const key = addMessage(file, occurrence.source, occurrence.message, { getSourceFile: () => ({ getLineAndCharacterOfPosition: () => ({ line: occurrence.line - 1 }) }), getStart: () => occurrence.start });
    }
    continue;
  }
  rawSources.push({ repo: file.repo, file: file.file, sha256: digest(text), text });
  const result = migrate(file, text);
  report.push({ repo: file.repo, file: file.file, sha256: file.sha256, edits: result.changes, metadata: result.metadata });
  if (result.text !== text) changes.push({ absolute, text: result.text, repo: file.repo, file: file.file });
}
if (process.argv.includes('--write')) {
  if (fs.existsSync(baseline) && !baselineSources) throw new Error('A source baseline already exists; do not apply this migration twice.');
  if (!baselineSources) fs.writeFileSync(baseline, JSON.stringify(rawSources));
  for (const change of changes) fs.writeFileSync(change.absolute, change.text);
}
const outputIndex = process.argv.indexOf('--catalog-out');
fs.writeFileSync(outputIndex === -1 ? path.join(out, 'full-staging.json') : process.argv[outputIndex + 1], JSON.stringify({ schemaVersion: 1, status: 'staging-not-runtime', messages: catalog, pending: [] }, null, 2) + '\n');
if (outputIndex === -1) {
  fs.writeFileSync(path.join(out, 'source-migration.json'), JSON.stringify({ schemaVersion: 1, written: process.argv.includes('--write'), baseline, files: report }, null, 2) + '\n');
  fs.writeFileSync(path.join(out, 'parent-messages.json'), JSON.stringify(parentMessages, null, 2) + '\n');
}
console.log(JSON.stringify({ write: process.argv.includes('--write'), changedFiles: changes.length, uniqueMessages: Object.keys(catalog).length, parentMessages: parentMessages.length, sourceEdits: report.reduce((sum, file) => sum + file.edits.length, 0) }, null, 2));
