import ts from 'typescript';
import fs from 'node:fs';
import path from 'node:path';
import { frontend, roots, parentOwned } from './config.mjs';
import { inventory } from './inventory.mjs';
let files = 0;
for (const file of inventory().files) {
  if (parentOwned(file.file) || file.html || file.file.endsWith('.json')) continue;
  const absolute = path.join(roots[file.repo], file.file), text = fs.readFileSync(absolute, 'utf8'), sf = ts.createSourceFile(file.file, text, ts.ScriptTarget.Latest, true, file.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const edits = [], names = new Set();
  function visit(node) {
    if (file.file.endsWith('/lib/api.ts') && ts.isParameter(node) && node.name.getText(sf) === 'onError' && node.type && ts.isFunctionTypeNode(node.type) && node.type.parameters.length === 1) {
      edits.push({ start: node.type.parameters[0].end, end: node.type.parameters[0].end, replacement: ', presentation?: MessageText' }); names.add('type MessageText');
    }
    if (file.file.endsWith('/lib/api.ts') && ts.isCallExpression(node) && node.expression.getText(sf) === 'onError' && node.arguments.length === 1) {
      const argument = node.arguments[0];
      if (ts.isCallExpression(argument) && /^(?:translate|i18nText)$/.test(argument.expression.getText(sf))) {
        const params = argument.arguments.map(value => value.getText(sf)).join(', ');
        names.add('messageSource'); names.add('message as streamMessage');
        edits.push({ start: argument.getStart(sf), end: argument.end, replacement: `messageSource(streamMessage(${params})), streamMessage(${params})` });
      } else if (argument.getText(sf) === 'error.error') {
        names.add('presentationValue'); edits.push({ start: argument.end, end: argument.end, replacement: `, presentationValue(error, 'message')` });
      }
    }
    if (file.file.endsWith('/lib/api.ts') && ts.isNewExpression(node) && node.expression.getText(sf) === 'EventSource' && node.arguments?.[0]?.getText(sf) === 'url') { names.add('localeURL'); edits.push({ start: node.arguments[0].getStart(sf), end: node.arguments[0].end, replacement: 'localeURL(url)' }); }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === 'streamAuditRecords' && node.arguments[6] && ts.isArrowFunction(node.arguments[6])) {
      const callback = node.arguments[6], parameter = callback.parameters[0];
      if (parameter && callback.parameters.length === 1 && /set[A-Za-z]*Error\(/.test(callback.body.getText(sf))) {
        names.add('type MessageText');
        const addition = ', presentation?: MessageText';
        if (callback.getText(sf).startsWith('(')) edits.push({ start: parameter.end, end: parameter.end, replacement: addition });
        else edits.push({ start: parameter.getStart(sf), end: parameter.end, replacement: `(${parameter.getText(sf)}${addition})` });
        function consumer(child) {
          if (ts.isCallExpression(child) && /^set[A-Za-z]*Error$/.test(child.expression.getText(sf)) && child.arguments[0]?.getText(sf) === parameter.name.getText(sf)) edits.push({ start: child.arguments[0].getStart(sf), end: child.arguments[0].end, replacement: `presentation ?? ${parameter.name.getText(sf)}` });
          ts.forEachChild(child, consumer);
        }
        consumer(callback.body);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf); if (!edits.length) continue;
  const imports = sf.statements.filter(ts.isImportDeclaration), bound = new Set(imports.flatMap(statement => statement.importClause?.namedBindings && ts.isNamedImports(statement.importClause.namedBindings) ? statement.importClause.namedBindings.elements.map(item => item.name.text) : []));
  const required = [...names].filter(name => !bound.has(name.replace(/^type /, '').split(' as ').at(-1)));
  if (required.length) {
    let module = path.posix.relative(path.posix.dirname(file.file), file.repo === 'netcap-pro' ? 'frontend/src/lib/i18n' : 'cmd/capture/webui/frontend/packages/netcap-ui/src/lib/i18n'); if (!module.startsWith('.')) module = './' + module;
    const position = imports.at(-1)?.end ?? sf.statements[0]?.getStart(sf) ?? 0;
    edits.push({ start: position, end: position, replacement: `\nimport { ${required.join(', ')} } from ${JSON.stringify(module)};\n` });
  }
  let output = text, boundary = text.length;
  for (const edit of edits.sort((a, b) => b.start - a.start)) { if (edit.end > boundary) throw new Error(`Overlapping stream changes: ${file.file}`); output = output.slice(0, edit.start) + edit.replacement + output.slice(edit.end); boundary = edit.start; }
  fs.writeFileSync(absolute, output); files++;
}
console.log(JSON.stringify({ streamProducerAndConsumerFiles: files }));
