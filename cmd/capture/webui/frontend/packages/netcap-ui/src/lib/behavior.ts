import type { FileInfo, StatusResponse } from './api';

export interface BehaviorScope {
  sensor: string;
  interface: string;
  vlans?: number[];
}

export interface BehaviorFact {
	bytes?: number;
	token?: string;
  scope: BehaviorScope;
  kind: string;
  srcIP?: string;
  dstIP?: string;
  mac?: string;
  protocol?: string;
  port?: number;
  value?: string;
  provenance?: string;
}

export interface BehaviorObservation {
  fact: BehaviorFact;
  firstSeen: number;
  lastSeen: number;
  samples: number;
}

export interface BehaviorSnapshot {
	labels?: Record<string, { fact: BehaviorFact; name: string; role?: string; notes?: string }>;
	corrections?: Record<string, BehaviorFact>;
	windowOverflow?: number;
	policy?: { windowNS: number; fanout: number; rdpAttempts: number; rateWindows: number; rateMultiplier: number; approvedSources?: string[] };
	approvedRates?: Record<string, { windows: number; packetsMean: number; bytesMean: number }>;
  schema: number;
  error?: string;
  mode: 'learning' | 'monitoring' | 'paused';
  resumeMode?: 'learning' | 'monitoring';
  version: number;
  baselineId: string;
  learningStarted: number;
  watermark: number;
  samples: number;
  overflow: number;
  outOfOrder: number;
  minLearningNS: number;
  minSamples: number;
  maxFacts: number;
  observed: Record<string, BehaviorObservation>;
  approved: Record<string, BehaviorFact>;
  suppressed: Record<string, string>;
  decisions: { at: number; action: string; reason: string; version: number; baselineId: string }[] | null;
}

export interface BehaviorTopology {
  nodes: { id: string; kind: string; name: string; address: string; scope: BehaviorScope; factId?: string }[];
  links: { source: string; target: string; kind: string; factId?: string }[];
  totalNodes: number;
  totalLinks: number;
  truncated: boolean;
}

export type BehaviorAction = 'approve' | 'pause' | 'resume' | 'relearn' | 'reset' | 'approve-changes' | 'suppress' | 'unsuppress';

export function behaviorSelection(status?: StatusResponse, files: FileInfo[] = []): string {
  if (status?.isServiceMode && status.sessionId) return `?sessionId=${encodeURIComponent(status.sessionId)}`;
  if (!status?.isLiveMode && status?.activeInputFile) {
    const exact = files.find(file => file.path === status.activeInputFile);
    const matches = files.filter(file => file.name === status.activeInputFile || file.path.endsWith(`/${status.activeInputFile}`));
    const selected = exact ?? (matches.length === 1 ? matches[0] : undefined);
    return `?inputFile=${encodeURIComponent(selected?.path ?? status.activeInputFile)}`;
  }
  return '';
}

export function scopeLabel(scope: BehaviorScope): string {
  return `${scope.sensor} / ${scope.interface}${scope.vlans?.length ? ` / VLAN ${scope.vlans.join('/')}` : ''}`;
}

export function factLabel(fact: BehaviorFact): string {
  if (fact.kind === 'device') return fact.mac ?? 'Unknown MAC';
  if (fact.kind === 'binding') return `${fact.srcIP} ↔ ${fact.mac}`;
  if (fact.kind === 'edge') return `${fact.srcIP} ↔ ${fact.dstIP}`;
  if (fact.kind === 'service' || fact.kind === 'resolver') return `${fact.srcIP} → ${fact.dstIP}:${fact.port}/${fact.protocol}`;
  if (fact.kind === 'dns') return `${fact.srcIP} → ${fact.value}`;
  if (fact.kind === 'traffic') return `${fact.srcIP} packet/byte volume`;
  return fact.value ?? `${fact.srcIP ?? ''} → ${fact.dstIP ?? ''}`;
}

export function learningReady(snapshot: BehaviorSnapshot): boolean {
  return snapshot.mode === 'learning' && snapshot.samples >= snapshot.minSamples &&
    snapshot.watermark - snapshot.learningStarted >= snapshot.minLearningNS &&
    snapshot.overflow === 0 && !snapshot.windowOverflow && Object.keys(snapshot.observed).length > 0 && !snapshot.error;
}

export async function behaviorRequest<T>(fetcher: typeof fetch, url: string, init?: RequestInit): Promise<T> {
  const response = await fetcher(url, init);
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(response.status === 404 ? 'No baseline for this capture. Enable capture or agent with -behavior.' : detail || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}
