import { copyFileSync, cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = process.env.NETCAP_ROOT ? resolve(process.env.NETCAP_ROOT) : resolve(frontend, '../../../..');
const publicLegal = resolve(frontend, 'public/legal');
const packageRoot = resolve(frontend, 'packages/netcap-ui');

rmSync(publicLegal, { recursive: true, force: true });
mkdirSync(publicLegal, { recursive: true });
copyFileSync(resolve(root, 'LICENSE'), resolve(publicLegal, 'LICENSE'));
cpSync(resolve(root, 'legal'), publicLegal, { recursive: true });

copyFileSync(resolve(root, 'LICENSE'), resolve(packageRoot, 'LICENSE'));
copyFileSync(resolve(root, 'legal/THIRD_PARTY_LICENSES.txt'), resolve(packageRoot, 'THIRD_PARTY_LICENSES.txt'));
copyFileSync(resolve(root, 'legal/THIRD_PARTY_RUST_LICENSES.txt'), resolve(packageRoot, 'THIRD_PARTY_RUST_LICENSES.txt'));
copyFileSync(resolve(root, 'legal/THIRD_PARTY_NOTICES.txt'), resolve(packageRoot, 'THIRD_PARTY_NOTICES.txt'));
cpSync(resolve(root, 'legal/licenses'), resolve(packageRoot, 'licenses'), { recursive: true });
