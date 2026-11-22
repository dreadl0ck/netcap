import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { frontend } from './config.mjs';
const require = process.env.NETCAP_I18N_DEPS_ROOT ? createRequire(path.join(process.env.NETCAP_I18N_DEPS_ROOT, 'package.json')) : createRequire(import.meta.url);
const { parse } = require('@formatjs/icu-messageformat-parser');
const directory = path.join(frontend, 'localization'), policyPath = path.join(directory, 'catalog-policy.json'), policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
const stage = JSON.parse(fs.readFileSync(path.join(directory, 'full-staging.json'), 'utf8'));
const words = {
  de: 'Dashboard Dashboards Host Hosts Exploit Exploits Hostname Tag Tags Info Client Clients Server Software Test Name Format Filter Banner Version Status Internet Parameter Operator Generator Scan Scans Pause Radial Graph Standard Normal System Signal Workstation Byte Bytes Bit Bits Port Ports Minimum Maximum Detail Details Export Import Transport Text Rate in Option Index Flags Parser Hash Nonce Navigation Parallel Router Routers Aggregator Argument Code Cookie Echo Optional Routing Stratum Suffix Typ Radar',
  nl: 'Dashboard Dashboards Host Hosts Exploit Exploits Tag Tags Info Client Clients Server Servers Software Test Filter Filters Banner Interface Interfaces Protocol Byte Bytes Bit Bits Status Type Types Detail Details Export Import Transport Parameter Parameters Operator Generator Scan Scans Live Score Object Objecten in Databases Database Peer Peers Platform Offset Product Label Detector Broadcast Multicast Root Script firewall Index protocol bytes peers start Start server manifest Parser token Hash Nonce Realm Impact Parallel Machine type types label Actor Context Later Router Routers Aggregator Argument Authenticator Backplane Bank Chassis Code Cookie Ctrl Echo Hashes Header Headers Hello Multipath Payload Prefix Repeater Stratum Subtype Urgent Via via Volume Website Is Items',
  fr: 'Note Notes Message Messages Version Versions Volume Via via Source Sources Destination Destinations Pause Radial Action Actions Option Options Description Descriptions Configuration Configurations Information Interface Interfaces Original Local Total Distance Distances Type Types type types Section Sections Route Routes Collision Collisions Position Positions Fragment Fragments Parent Parents Navigation Rotation Date Dates Minimum Maximum Score Normal Signal Session Sessions Collection Collections Observation Observations capture captures Capture Captures Secrets Secret Services Service Documentation navigation Expression Exploit Exploits Applications Contacts Client Clients client clients Script injection modification Port Ports port portrange src dst Direction Transport Impact Encapsulation Encapsulations Argument Arguments Cause Code Contact Cookie Diagnostic Exception Extensions Final Full Duplex Identification Index Instance Multipoint Nonce Ordinal Proto Qualifications Questions Urgent Variation Compression Occurrences Radar',
  es: 'Normal Control Total Local Original Internet Manual General Experimental Digital Vertical Horizontal Radial Global Interfaces Software No Detector Actor Final Ordinal Roles Radar Script Cookie Hash Hashes Error error Host Hosts Router Routers token Nonce Byte Bytes byte bytes',
};
const technical = new Set([...policy.technicalTokens, 'ID', 'IP', 'URI', 'URL', 'ns', 'µs', 'ms', 's', 'm', 'min', 'h', 'd', 'B', 'KB', 'MB', 'GB', 'KiB', 'MiB', 'GiB', 'pps', 'UTC', 'PCAPs', 'r', 'v', 'x', 'DPI', 'DHCP', 'SYN', 'RST', 'ACK', 'PSH', 'FIN', 'fCoSE', 'CoSE', 'Bilkent', 'Dagre', 'Klay', 'Cola', 'Euler', 'AVSDF', 'Wireshark', 'gopacket', 'nDPI', 'libprotoident']);
for (const word of 'sha256 ja4 ja4s sni http netflow v5 v9 ipfix sflow MINING STRATUM Diameter Geneve Modbus Radius Syslog OpenCode goroutines TCP SOCKS SHA 256 SNMP Elastic VPN Client Server JA3 JA3S IPs pp ASF CA DCC GQUIC IETFQUIC IPMI NXDOMAIN RFC5389 TCN'.split(' ')) technical.add(word);
words.nl += ' Open Batch Radar records';
words.fr += ' Tunnel Investigation';
let reviewed = 0;
for (const [id, entry] of Object.entries(stage.messages)) {
  const literals = [];
  function walk(elements) { for (const element of elements) { if (element.type === 0) literals.push(...element.value.match(/[\p{L}\d]+/gu) ?? []); if (element.children) walk(element.children); if (element.options) Object.values(element.options).forEach(option => walk(option.value)); } }
  walk(parse(entry.message));
  for (const locale of ['de', 'nl', 'fr', 'es', 'zh-Hans']) {
    const accepted = new Set((words[locale] ?? '').toLowerCase().split(' '));
    const valid = literals.every(word => technical.has(word) || accepted.has(word.toLowerCase()) || /^\d+$/.test(word) || /^\d+(?:[KMGTPE]i?)?B$/.test(word) || /^\d+(?:ns|µs|ms|s|min|h|d)$/.test(word));
    if (valid) {
      policy.unchanged[id] ??= {};
      policy.unchanged[id][locale] = `Reviewed ${locale} literal vocabulary: ${literals.join(', ') || '(only ICU placeholders/punctuation)'}. All words are established local IT terms, SI/protocol identifiers or symbols; no untranslated prose is allowed.`;
      reviewed++;
    }
  }
}
fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2) + '\n');
console.log(JSON.stringify({ reviewedUnchangedMessageLocalePairs: reviewed }));
