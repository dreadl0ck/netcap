/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { formatNumber, translate } from './i18n';

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
  const options = { minimumSignificantDigits: 3, maximumSignificantDigits: 3 };
  if (ns < 1e6) return `${formatNumber(ns / 1e3, options)} µs`;
  if (ns < 1e9) return `${formatNumber(ns / 1e6, options)} ms`;
  return `${formatNumber(ns / 1e9, options)} s`;
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
  if (summary.unanswered > 0) flags.push(translate('ui:dns.transactions.unanswered', { count: summary.unanswered }));
  if (summary.unsolicited > 0) flags.push(translate('ui:dns.transactions.unsolicited', { count: summary.unsolicited }));
  if (summary.retransmissions > 0) flags.push(translate('ui:dns.transactions.retransmitted', { count: summary.retransmissions }));
  if (summary.late > 0) flags.push(translate('ui:dns.transactions.late', { count: summary.late }));
  if ((summary.reordered ?? 0) > 0) flags.push(translate('ui:dns.transactions.reordered', { count: summary.reordered }));
  if (summary.rttTruncated) flags.push(translate('ui:dns.transactions.truncated'));
  return flags;
}
