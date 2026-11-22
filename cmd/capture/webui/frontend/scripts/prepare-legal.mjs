import { copyFileSync, cpSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fontPackage, fontVersion, prepareFonts, verifyFonts } from './prepare-fonts.mjs';

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = process.env.NETCAP_ROOT ? resolve(process.env.NETCAP_ROOT) : resolve(frontend, '../../../..');
const publicLegal = resolve(frontend, 'public/legal');
const packageRoot = resolve(frontend, 'packages/netcap-ui');

prepareFonts();
verifyFonts();
if (!readFileSync(resolve(root, 'legal/THIRD_PARTY_LICENSES.txt'), 'utf8').includes(`${fontPackage} ${fontVersion}\nLicense inventory: OFL-1.1`)) {
  throw new Error('Font supplier notice missing; run go run ./internal/tools/licenses from the Netcap root');
}

rmSync(publicLegal, { recursive: true, force: true });
mkdirSync(publicLegal, { recursive: true });
copyFileSync(resolve(root, 'LICENSE'), resolve(publicLegal, 'LICENSE'));
cpSync(resolve(root, 'legal'), publicLegal, { recursive: true });

copyFileSync(resolve(root, 'LICENSE'), resolve(packageRoot, 'LICENSE'));
copyFileSync(resolve(root, 'legal/THIRD_PARTY_LICENSES.txt'), resolve(packageRoot, 'THIRD_PARTY_LICENSES.txt'));
copyFileSync(resolve(root, 'legal/THIRD_PARTY_RUST_LICENSES.txt'), resolve(packageRoot, 'THIRD_PARTY_RUST_LICENSES.txt'));
copyFileSync(resolve(root, 'legal/THIRD_PARTY_NOTICES.txt'), resolve(packageRoot, 'THIRD_PARTY_NOTICES.txt'));
cpSync(resolve(root, 'legal/licenses'), resolve(packageRoot, 'licenses'), { recursive: true });
