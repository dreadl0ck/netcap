/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

/** Capture-time DNS query/response pairing for one domain (backend DNSTransactionSummary). */
export interface DNSTransactionSummary {
  queries: number;
  retransmissions: number;
  answered: number;
  late: number;
  unsolicited: number;
  reordered?: number;
  /** Lower bound: queries minus responses paired to them. */
  unanswered: number;
  rttSamples: number;
  rttMedianNs: number;
  rttP95Ns: number;
  rttTruncated?: boolean;
}

/** Formats a nanosecond duration as µs, ms or s with three significant digits. */
export function formatDurationNs(ns: number): string {
  if (!Number.isFinite(ns) || ns < 0) return '—';
  if (ns < 1e6) return `${(ns / 1e3).toPrecision(3)} µs`;
  if (ns < 1e9) return `${(ns / 1e6).toPrecision(3)} ms`;
  return `${(ns / 1e9).toPrecision(3)} s`;
}

/** Median RTT text, or a dash when no response was paired. */
export function medianRTT(summary?: DNSTransactionSummary): string {
  if (!summary || summary.rttSamples === 0) return '—';
  return `${summary.rttTruncated ? '~' : ''}${formatDurationNs(summary.rttMedianNs)}`;
}

/** Sort key for RTT columns: unpaired domains sort after every measured one. */
export function rttSortKey(summary?: DNSTransactionSummary): number {
  return summary && summary.rttSamples > 0 ? summary.rttMedianNs : Number.POSITIVE_INFINITY;
}

/**
 * Pairing anomalies an analyst should look at. A response without a matching
 * query (unsolicited) can be spoofing or simply capture loss; unanswered
 * queries can be resolver failure, filtering or missing visibility.
 */
export function transactionFlags(summary?: DNSTransactionSummary): string[] {
  if (!summary) return [];
  const flags: string[] = [];
  if (summary.unanswered > 0) flags.push(`${summary.unanswered} unanswered`);
  if (summary.unsolicited > 0) flags.push(`${summary.unsolicited} unsolicited`);
  if (summary.retransmissions > 0) flags.push(`${summary.retransmissions} retransmitted`);
  if (summary.late > 0) flags.push(`${summary.late} late`);
  if ((summary.reordered ?? 0) > 0) flags.push(`${summary.reordered} clock-order unknown`);
  if (summary.rttTruncated) flags.push('RTT sample limit reached');
  return flags;
}
