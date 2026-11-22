import ts from 'typescript';
import path from 'node:path';
import { frontend, pro } from './config.mjs';

const root = path.join(frontend, 'packages/netcap-ui/src/lib');
const modules = ['i18n.ts', 'i18n/format.ts', 'i18n/mui.ts', 'i18n/direct.ts', 'i18n/removed.ts'];
const temporary = process.env.NETCAP_I18N_DEPS_ROOT;
const options = {
  target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler,
  strict: true, noEmit: true, skipLibCheck: true, esModuleInterop: true, resolveJsonModule: true,
  lib: ['lib.es2022.d.ts', 'lib.dom.d.ts', 'lib.dom.iterable.d.ts'], baseUrl: frontend,
  ...(temporary ? { paths: Object.fromEntries(['i18next', 'i18next-icu', 'react-i18next', 'intl-messageformat'].map(name => [name, [path.join(temporary, 'node_modules', name)]])) } : {}),
};
const packageRoot = process.argv.includes('--pro') ? path.join(pro, 'frontend') : path.join(frontend, 'packages/netcap-ui');
const config = ts.readConfigFile(path.join(packageRoot, 'tsconfig.json'), ts.sys.readFile);
const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, packageRoot);
const paths = { ...parsed.options.paths, ...options.paths };
if (process.argv.includes('--pro')) {
  paths['@/*'] = [path.join(pro, 'frontend/src/*')];
  paths['@dreadl0ck/netcap-ui/i18n'] = [path.join(root, 'i18n.ts')];
  paths['@dreadl0ck/netcap-ui/i18n/*'] = [path.join(root, 'i18n/*')];
}
const program = ts.createProgram(process.argv.includes('--all') ? parsed.fileNames : modules.map(file => path.join(root, file)), { ...parsed.options, ...options, paths, noEmit: true, jsx: ts.JsxEmit.ReactJSX });
const diagnostics = ts.getPreEmitDiagnostics(program);
if (diagnostics.length) {
  if (process.argv.includes('--brief')) for (const diagnostic of diagnostics) { const position = diagnostic.file && diagnostic.start !== undefined ? diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start) : null; console.error(`${diagnostic.file ? path.relative(frontend, diagnostic.file.fileName) : 'compiler'}${position ? ':' + (position.line + 1) + ':' + (position.character + 1) : ''} TS${diagnostic.code}: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`); }
  else console.error(ts.formatDiagnosticsWithColorAndContext(diagnostics, { getCurrentDirectory: () => frontend, getCanonicalFileName: file => file, getNewLine: () => '\n' }));
  process.exitCode = 1;
} else console.log('Localization modules: TypeScript check passed');
