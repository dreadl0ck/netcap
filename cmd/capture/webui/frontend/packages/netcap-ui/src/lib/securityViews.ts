/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

/**
 * Explore views worth opening on: each one answers a question an analyst asks
 * of a capture. The Explore page picks one at random from those whose record
 * type and field exist in the active capture, instead of cycling through every
 * record type (which landed on views such as IPv6HopByHop or a
 * multicast-listener flag).
 *
 * Field names are the backend's /api/chart/fields names. Line/area/scatter need
 * a numeric field; pie/bar/wordcloud/funnel take categorical ones. Sankey
 * ignores the field and draws source -> destination flows.
 */
export interface SecurityView {
  type: string;
  field: string;
  chartType: 'pie' | 'bar' | 'wordcloud' | 'funnel' | 'sankey' | 'line' | 'area' | 'scatter';
  question: string;
}

export const SECURITY_VIEWS: SecurityView[] = [
  // Detections
  { type: 'Alert', field: 'Name', chartType: 'pie', question: 'Which detections fired most?' },
  { type: 'Alert', field: 'Severity', chartType: 'pie', question: 'How severe are the alerts?' },
  { type: 'Alert', field: 'MITRE', chartType: 'bar', question: 'Which ATT&CK techniques were observed?' },
  { type: 'Alert', field: 'SrcIP', chartType: 'bar', question: 'Which hosts trigger the most alerts?' },
  { type: 'Alert', field: 'SrcIP', chartType: 'sankey', question: 'Who alerts against whom?' },

  // Connections
  { type: 'Connection', field: 'DstPort', chartType: 'bar', question: 'Which destination ports are used?' },
  { type: 'Connection', field: 'ApplicationProto', chartType: 'pie', question: 'Which application protocols are in use?' },
  { type: 'Connection', field: 'ServerPortName', chartType: 'pie', question: 'Which services are contacted?' },
  { type: 'Connection', field: 'DstIP', chartType: 'bar', question: 'Which destinations get the most connections?' },
  { type: 'Connection', field: 'DstGeoLocation', chartType: 'pie', question: 'Where does traffic go?' },
  { type: 'Connection', field: 'BytesClientToServer', chartType: 'line', question: 'When were large uploads sent (exfiltration)?' },
  { type: 'Connection', field: 'Duration', chartType: 'scatter', question: 'Are there long-lived connections (C2, tunnels)?' },
  { type: 'Connection', field: 'NumRSTFlags', chartType: 'line', question: 'When were connections refused (scanning)?' },
  { type: 'Connection', field: 'SrcIP', chartType: 'sankey', question: 'Who talks to whom?' },

  // DNS
  { type: 'DNS', field: 'Questions.Name', chartType: 'wordcloud', question: 'Which names are resolved?' },
  { type: 'DNS', field: 'QueryNameTLD', chartType: 'pie', question: 'Which top-level domains are queried?' },
  { type: 'DNS', field: 'ResponseCodeName', chartType: 'pie', question: 'How many lookups fail (NXDOMAIN, DGA)?' },
  { type: 'DNS', field: 'QueryNameLength', chartType: 'scatter', question: 'Are there unusually long names (tunnelling)?' },
  { type: 'DNS', field: 'SubdomainCount', chartType: 'line', question: 'Are deep subdomains queried over time (tunnelling)?' },

  // Web
  { type: 'HTTP', field: 'Host', chartType: 'bar', question: 'Which web hosts are contacted?' },
  { type: 'HTTP', field: 'RequestHeader.User-Agent', chartType: 'bar', question: 'Which clients and tools make requests?' },
  { type: 'HTTP', field: 'Method', chartType: 'pie', question: 'Which HTTP methods are used?' },
  { type: 'HTTP', field: 'ResContentTypeDetected', chartType: 'pie', question: 'What content is downloaded?' },

  // TLS
  { type: 'TLSClientHello', field: 'SNI', chartType: 'wordcloud', question: 'Which TLS servers are requested?' },
  { type: 'TLSClientHello', field: 'Ja4', chartType: 'bar', question: 'Which TLS client stacks (JA4) are present?' },
  { type: 'TLSClientHello', field: 'IsKnownMalware', chartType: 'pie', question: 'Do any JA4 fingerprints match known malware?' },
  { type: 'TLSServerHello', field: 'Ja4S', chartType: 'bar', question: 'Which TLS server stacks (JA4S) answer?' },
  { type: 'TLSCertificate', field: 'IssuerOrganization', chartType: 'pie', question: 'Who issued the certificates?' },
  { type: 'TLSCertificate', field: 'IsSelfSigned', chartType: 'pie', question: 'How many certificates are self-signed?' },
  { type: 'TLSCertificate', field: 'SignatureAlgorithm', chartType: 'pie', question: 'Are weak signature algorithms in use?' },

  // Credentials and accounts
  { type: 'Secret', field: 'Service', chartType: 'pie', question: 'Which protocols leak credentials?' },
  { type: 'Kerberos', field: 'MessageType', chartType: 'pie', question: 'What Kerberos activity is there?' },
  { type: 'SMB', field: 'CommandName', chartType: 'pie', question: 'What SMB operations are performed?' },
  { type: 'SMB', field: 'ShareName', chartType: 'bar', question: 'Which SMB shares are accessed?' },
  { type: 'SSH', field: 'SoftwareVersion', chartType: 'pie', question: 'Which SSH implementations are used?' },

  // Software and exposure
  { type: 'Software', field: 'Product', chartType: 'wordcloud', question: 'Which software is running?' },
  { type: 'Software', field: 'IsEndOfLife', chartType: 'pie', question: 'How much software is end-of-life?' },
  { type: 'Vulnerability', field: 'Severity', chartType: 'pie', question: 'How severe are the known vulnerabilities?' },
  { type: 'Vulnerability', field: 'Software.Product', chartType: 'bar', question: 'Which products are vulnerable?' },
  { type: 'Exploit', field: 'Platform', chartType: 'pie', question: 'Which platforms have public exploits?' },
  { type: 'Service', field: 'Product', chartType: 'pie', question: 'Which server products are exposed?' },
  { type: 'Service', field: 'PortName', chartType: 'bar', question: 'Which services are listening?' },

  // Files and mail
  { type: 'File', field: 'TrueFileType', chartType: 'pie', question: 'What file types were transferred?' },
  { type: 'File', field: 'Entropy', chartType: 'scatter', question: 'Are there high-entropy (packed or encrypted) files?' },
  { type: 'File', field: 'Host', chartType: 'bar', question: 'Which hosts served files?' },
  { type: 'Mail', field: 'From', chartType: 'bar', question: 'Who sent mail?' },
  { type: 'Mail', field: 'SPFResult', chartType: 'pie', question: 'Does sender authentication (SPF) pass?' },

  // Assets
  { type: 'DeviceProfile', field: 'DeviceManufacturer', chartType: 'pie', question: 'Which device vendors are on the network?' },
  { type: 'DeviceProfile', field: 'OS', chartType: 'pie', question: 'Which operating systems are present?' },
  { type: 'Host', field: 'Geolocation', chartType: 'pie', question: 'Where are the hosts located?' },
];

/** Views whose record type the capture contains. */
export function viewsForTypes(available: Iterable<string>): SecurityView[] {
  const set = new Set(available);
  return SECURITY_VIEWS.filter(v => set.has(v.type));
}

/** Views for one record type whose field the capture actually populated. */
export function viewsForFields(type: string, fields: Iterable<string>): SecurityView[] {
  const set = new Set(fields);
  return SECURITY_VIEWS.filter(v => v.type === type && set.has(v.field));
}

const LAST_VIEW_KEY = 'explore-last-security-view';

const viewKey = (v: SecurityView) => `${v.type}|${v.field}|${v.chartType}`;

/**
 * Picks a random view, avoiding the one shown last time when there is a
 * choice, so reopening Explore shows something new.
 */
export function pickRandomView(candidates: SecurityView[], random: () => number = Math.random): SecurityView | undefined {
  if (candidates.length === 0) return undefined;
  let last: string | null = null;
  try { last = localStorage.getItem(LAST_VIEW_KEY); } catch { /* storage unavailable */ }
  const pool = candidates.length > 1 ? candidates.filter(v => viewKey(v) !== last) : candidates;
  const view = pool[Math.min(pool.length - 1, Math.floor(random() * pool.length))];
  try { localStorage.setItem(LAST_VIEW_KEY, viewKey(view)); } catch { /* storage unavailable */ }
  return view;
}
