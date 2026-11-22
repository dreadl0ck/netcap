import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { frontend, locales } from './config.mjs';
const require = process.env.NETCAP_I18N_DEPS_ROOT ? createRequire(path.join(process.env.NETCAP_I18N_DEPS_ROOT, 'package.json')) : createRequire(import.meta.url);
const { parse } = require('@formatjs/icu-messageformat-parser');
const root = path.join(frontend, 'localization');
const stage = JSON.parse(fs.readFileSync(path.join(root, 'full-staging.json'), 'utf8'));
const file = path.join(root, 'catalog-policy.json');
const policy = JSON.parse(fs.readFileSync(file, 'utf8'));
delete policy.sourceUnchanged.Status.fr;
const tokens = new Set([...policy.technicalTokens.flatMap(token => [token, ...token.split(/[\s/]+/)]), 'ns', 'µs', 'ms', 's', 'min', 'h', 'd', 'B', 'KB', 'MB', 'GB', 'KiB', 'MiB', 'GiB', 'bit', 'bits', 'bit/s', 'UTC', 'IP', 'ID', 'VLAN', 'VLANs', 'ASN', 'AS', 'UI', 'PRO', 'Pro', 'NETCAP', 'Web', 'TCP/IP', 'DNS', 'UDP', 'TCP', 'HTTP', 'HTTPS', 'ARP', 'ICMP', 'ACK', 'RST', 'SYN', 'FIN', 'PSH', 'URG', 'ECE', 'CWR', 'NS', 'SNI', 'ALPN', 'RTT', 'TLS', 'CSV', 'JSON', 'XML', 'YAML', 'SSL', 'QUIC', 'DHCP', 'DPI', 'nDPI', 'libprotoident', 'Wireshark', 'pcap', 'pcapng', 'CT', 'SHA', 'SHA256', 'MD5', 'LLDP', 'CDP', 'NTP', 'SIP', 'RDP', 'FTP', 'SMTP', 'POP3', 'IMAP']);
for (const token of 'TOR SOCKS IRC TELNET P2P BitTorrent JA4L-C JA4L-S MMDB SQLite DB-IP Lite MaxMind GeoLite2 SNIs SHA-256 PUT PATCH DELETE HSTS CSP X-Content-Type-Options X-Frame-Options X-XSS-Protection Referrer-Policy CORS X-Powered-By X-Forwarded-For X-Real-IP User-Agent Referer ICMPv4 Ethernet MTU OK OPENVPN WIREGUARD VNC TEAMVIEWER MYSQL POSTGRES MONGODB curl wget python powershell exe dll scr bat ps1 vbs CISA KEV CTP CROB Zabbix Cnonce Etype Nc Qop Scts Seq QoP SPN Call-ID TLDs'.split(' ')) tokens.add(token);
const schema = JSON.parse(fs.readFileSync(path.join(frontend, 'packages/netcap-ui/src/lib/i18n/schema-labels.json'), 'utf8'));
for (const id of Object.keys(schema.types)) if (/[a-z][A-Z]|[A-Z]{2,}|\d/.test(id)) tokens.add(id);
let added = 0;
for (const [key, entry] of Object.entries(stage.messages)) {
  const words = [];
  function walk(elements) { for (const element of elements) { if (element.type === 0) words.push(...element.value.match(/[\p{L}\d_-]+/gu) ?? []); if (element.children) walk(element.children); if (element.options) Object.values(element.options).forEach(option => walk(option.value)); } }
  walk(parse(entry.message));
  if (words.every(word => tokens.has(word) || /^\d+$/.test(word))) {
    policy.unchanged[key] ??= {};
    for (const locale of locales.slice(1)) policy.unchanged[key][locale] = `ICU AST literal parts contain only placeholders, punctuation and invariant technical tokens: ${words.join(', ') || '(none)'}.`;
    added++;
  }
}
fs.writeFileSync(file, JSON.stringify(policy, null, 2) + '\n');
console.log(JSON.stringify({ invariantTechnicalPatterns: added }));
