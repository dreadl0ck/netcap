import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const fontPackage = '@fontsource-variable/noto-sans-sc';
export const fontVersion = '5.3.1';
export const fontFamily = 'Noto Sans SC Variable';
export const fontPath = '/static/fonts/noto-sans-sc/';
export const byteLimit = 5_000_000;
const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(join(frontend, 'package.json'));
const digest = data => createHash('sha256').update(data).digest('hex');

export function fontInputs() {
  const source = dirname(require.resolve(`${fontPackage}/package.json`));
  const pkg = JSON.parse(readFileSync(join(source, 'package.json'), 'utf8'));
  if (pkg.version !== fontVersion || pkg.license !== 'OFL-1.1') throw new Error('Unexpected Noto Sans SC package version/license');
  const upstream = readFileSync(join(source, 'index.css'), 'utf8');
  const files = new Map();
  const css = upstream.replace(/url\(([^)]+)\)/g, (_, url) => {
    if (!/^\.\/files\/noto-sans-sc-[a-z0-9-]+-wght-normal\.woff2$/.test(url)) throw new Error(`Unexpected font URL: ${url}`);
    const name = basename(url);
    const data = readFileSync(join(source, 'files', name));
    if (data.toString('ascii', 0, 4) !== 'wOF2') throw new Error(`Invalid WOFF2: ${name}`);
    files.set(name, data);
    return `url(./${name})`;
  });
  const faces = [...css.matchAll(/@font-face\s*\{([^}]+)\}/g)];
  if (faces.length !== files.size || !faces.length || faces.some(([, face]) => !face.includes(`'${fontFamily}'`) || !/font-weight:\s*100 900;/.test(face) || !/unicode-range:\s*U\+/i.test(face))) throw new Error('Expected one variable face per Unicode subset');
  const license = readFileSync(join(source, 'LICENSE'));
  if (!license.toString().includes('SIL OPEN FONT LICENSE')) throw new Error('Missing font supplier terms');
  files.set('index.css', Buffer.from(`/* ${fontPackage} ${fontVersion}; OFL-1.1. See LICENSE. */\n${css}`));
  files.set('LICENSE', license);
  const fontBytes = [...files].filter(([name]) => name.endsWith('.woff2')).reduce((n, [, data]) => n + data.length, 0);
  const totalBytes = [...files.values()].reduce((n, data) => n + data.length, 0);
  if (totalBytes >= byteLimit) throw new Error(`Font bundle exceeds ${byteLimit} bytes: ${totalBytes}`);
  return { files, fontBytes, totalBytes, subsets: faces.length };
}

export function prepareFonts(output = join(frontend, 'public', fontPath)) {
  const input = fontInputs();
  rmSync(output, { recursive: true, force: true });
  mkdirSync(output, { recursive: true });
  for (const [name, data] of input.files) writeFileSync(join(output, name), data);
  const manifest = {
    package: fontPackage, version: fontVersion, family: fontFamily,
    fontBytes: input.fontBytes, totalBytes: input.totalBytes, subsets: input.subsets,
    files: Object.fromEntries([...input.files].map(([name, data]) => [name, { bytes: data.length, sha256: digest(data) }])),
  };
  writeFileSync(join(output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

export function verifyFonts(output = join(frontend, 'public', fontPath)) {
  const input = fontInputs();
  const manifest = JSON.parse(readFileSync(join(output, 'manifest.json'), 'utf8'));
  if (manifest.package !== fontPackage || manifest.version !== fontVersion || manifest.family !== fontFamily || manifest.fontBytes !== input.fontBytes || manifest.totalBytes !== input.totalBytes || manifest.subsets !== input.subsets) throw new Error('Stale font manifest');
  const names = readdirSync(output).sort();
  if (JSON.stringify(names) !== JSON.stringify([...input.files.keys(), 'manifest.json'].sort())) throw new Error('Missing or surplus packaged font assets');
  for (const [name, expected] of input.files) {
    const actual = readFileSync(join(output, name));
    if (!actual.equals(expected) || manifest.files[name]?.sha256 !== digest(actual)) throw new Error(`Stale font asset: ${name}`);
  }
  const manifestBytes = readFileSync(join(output, 'manifest.json')).length;
  if (input.totalBytes + manifestBytes >= byteLimit) throw new Error('Packaged font assets exceed byte budget');
  return { ...manifest, shippedBytes: input.totalBytes + manifestBytes };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (!process.argv.includes('--check')) prepareFonts();
  const { package: name, version, subsets, fontBytes, shippedBytes } = verifyFonts();
  console.log(JSON.stringify({ package: name, version, subsets, fontBytes, shippedBytes }));
}
