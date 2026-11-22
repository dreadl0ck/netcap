import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const frontend = fileURLToPath(new URL('../../', import.meta.url));
export const netcap = path.resolve(frontend, '../../../..');
export const pro = process.env.NETCAP_PRO_ROOT ?? path.resolve(netcap, '../netcap-pro');
export const roots = { netcap, 'netcap-pro': pro };
export const locales = ['en', 'de', 'nl', 'fr', 'es', 'zh-Hans'];
export const catalogsRoot = path.join(frontend, 'packages/netcap-ui/src/lib/i18n/catalogs');
export const productionRoots = [
  { repo: 'netcap', directory: path.join(frontend, 'src') },
  { repo: 'netcap', directory: path.join(frontend, 'packages/netcap-ui/src') },
  { repo: 'netcap-pro', directory: path.join(pro, 'frontend/src') },
];
export const htmlFiles = [
  { repo: 'netcap', file: path.join(frontend, 'index.html') },
  { repo: 'netcap-pro', file: path.join(pro, 'frontend/index.html') },
];

export function parentOwned(file) {
  return /(?:^|\/)(?:main\.tsx|index\.html|Layout\.tsx|NetcapProvider\.tsx|index\.[jt]sx?|package\.json|[^/]*lock[^/]*)$/.test(file)
    || /\/(?:adapters|bindings|preferences)\//.test(file)
    || /\/(?:Preferences|AppearanceControls|PresentationControls|LanguageControls|LocaleControls)[^/]*\.[jt]sx?$/.test(file);
}

export function namespaceFor(file, source) {
  if (/^Direct-download builds\b/.test(source)) return 'direct';
  if (/^(?:YARA Rules(?::|$)|Configure packet injection and manipulation rules\.|Configure Deep Packet Inspection modules\.|View available network interfaces for live packet capture and monitoring\.|Manage GeoIP, vulnerability, and MAC vendor databases\.|Inspect read-only protocol signatures, source evidence and capture coverage\.)/.test(source)) return 'removed';
  if (/\/(?:LicenseGate|UpdateBanner)\.tsx$/.test(file)
    || /\b(?:license key|buy license|purchase a license|free trial|license server|check for updates|install update|payment|checkout)\b/i.test(source)) return 'direct';
  if (/\/(?:graph|similarity|traffic-3d|mcp|interfaces|service-signatures|enrichment|firewall)\.tsx$/.test(file)
    || /\/(?:MachineBuilder|MachineRunner|TrafficScene|WiresharkButton|BehaviorDesktopAlerts|DatabaseBootstrap)\.tsx$/.test(file)
    || /\/(?:Dbs|Dpi|Inject|Interfaces|Yara|Probes)Page\.tsx$/.test(file)
    || /\/edition\.tsx$/.test(file)
    || /\/lib\/(?:machineTypes|releaseHighlights)\.(?:ts|json)$/.test(file)) return 'removed';
  return 'ui';
}

export function sourceFilePath(repo, relative) {
  if (!roots[repo]) throw new Error(`Unknown repository: ${repo}`);
  const absolute = path.resolve(roots[repo], relative);
  if (!absolute.startsWith(roots[repo] + path.sep)) throw new Error(`Path escapes repository: ${relative}`);
  return absolute;
}
