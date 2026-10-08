// Related-evidence contract served by /api/evidence/related (schema 1).

export type EvidenceSelector =
  | { id: string }
  | { type: string; ordinal: number }
  | { observationId: string }
  | { type: string; communityId: string; time: string };

export interface EvidenceField { name: string; value: string }
export interface EvidenceRecord { id?: string; fileSha256?: string; type: string; ordinal: number; timestamp: number; communityId?: string; summary?: EvidenceField[] }
export type EvidenceLinkKind = 'same-connection' | 'same-flow' | 'alert' | 'dns-resolution' | 'resolved-connection';
export interface EvidenceLink { kind: EvidenceLinkKind; basis: string; record: EvidenceRecord }
export interface EvidenceSession { observationId?: string; communityId: string; first: number; last: number; srcIp: string; srcPort: string; dstIp: string; dstPort: string; ordinal: number }
export interface RelatedEvidence {
  schema: 1;
  target: EvidenceRecord;
  session: EvidenceSession | null;
  links: EvidenceLink[];
  truncated: boolean;
  indexed: number;
  limits: { enabled: boolean; windowNs: number; maxRecords: number; maxLinks: number };
  notes: string[];
}

const kinds: EvidenceLinkKind[] = ['same-connection', 'same-flow', 'alert', 'dns-resolution', 'resolved-connection'];

export const linkKindLabels: Record<EvidenceLinkKind, string> = {
  'same-connection': 'Same connection',
  'same-flow': 'Same flow',
  alert: 'Alert',
  'dns-resolution': 'Resolved by DNS',
  'resolved-connection': 'Connection to answer',
};

const isRecord = (r: any): r is EvidenceRecord =>
  r && typeof r.type === 'string' && Number.isInteger(r.ordinal) && typeof r.timestamp === 'number' &&
  (r.summary === undefined || (Array.isArray(r.summary) && r.summary.length <= 32 && r.summary.every((f: any) => typeof f?.name === 'string' && typeof f?.value === 'string')));

export function parseRelatedEvidence(body: any): RelatedEvidence | null {
  if (!body || body.schema !== 1 || !isRecord(body.target) || !Array.isArray(body.links) || body.links.length > 10000 ||
    !body.links.every((l: any) => kinds.includes(l?.kind) && typeof l?.basis === 'string' && isRecord(l?.record)) ||
    typeof body.truncated !== 'boolean' || typeof body.indexed !== 'number' || !Array.isArray(body.notes)) return null;
  if (body.session !== null && (typeof body.session?.first !== 'number' || typeof body.session?.last !== 'number')) return null;
  return body as RelatedEvidence;
}

// Exact integer text of a top-level JSON number; JSON.parse would round
// nanosecond timestamps above 2^53.
function rawInteger(json: string, key: string): string | undefined {
  const match = new RegExp(`"${key}"\\s*:\\s*(-?\\d+)`).exec(json);
  return match?.[1];
}

/** Selects the record an alert was raised on, from its matched-record JSON. */
export function selectorForAlert(recordType: string, matchedRecord: string): EvidenceSelector | null {
  if (!matchedRecord || matchedRecord.length > 1 << 20) return null;
  const type = recordType.replace(/^NC_/, '');
  const communityId = /"CommunityID"\s*:\s*"([^"]+)"/.exec(matchedRecord)?.[1];
  const time = rawInteger(matchedRecord, type === 'Connection' ? 'TimestampFirst' : 'Timestamp');
  if (!type || !communityId?.startsWith('1:') || !time) return null;
  return { type, communityId, time };
}
