/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

import { describe, it, expect } from 'vitest';

import { formatDurationNs, medianRTT, rttSortKey, transactionFlags, type DNSTransactionSummary } from '../lib/dnsTransactions';

const summary = (over: Partial<DNSTransactionSummary> = {}): DNSTransactionSummary => ({
  queries: 3, retransmissions: 0, answered: 3, late: 0, unsolicited: 0, unanswered: 0,
  rttSamples: 3, rttMedianNs: 12_345_678, rttP95Ns: 40_000_000, ...over,
});

describe('dnsTransactions', () => {
  it('makes unavailable clock order and capped sampling visible', () => {
    expect(transactionFlags(summary({ reordered:2, rttTruncated:true }))).toEqual(['2 clock-order unknown','RTT sample limit reached']);
    expect(medianRTT(summary({ rttTruncated:true }))).toBe('~12.3 ms');
  });
  it('formats durations by magnitude', () => {
    expect(formatDurationNs(850)).toBe('0.850 µs');
    expect(formatDurationNs(12_345_678)).toBe('12.3 ms');
    expect(formatDurationNs(31e9)).toBe('31.0 s');
    expect(formatDurationNs(-1)).toBe('—');
    expect(formatDurationNs(Number.NaN)).toBe('—');
  });

  it('shows no RTT without paired responses', () => {
    expect(medianRTT(undefined)).toBe('—');
    expect(medianRTT(summary({ rttSamples: 0, rttMedianNs: 0 }))).toBe('—');
    expect(medianRTT(summary())).toBe('12.3 ms');
  });

  it('sorts unmeasured domains after measured ones', () => {
    expect(rttSortKey(undefined)).toBe(Number.POSITIVE_INFINITY);
    expect(rttSortKey(summary({ rttSamples: 0 }))).toBe(Number.POSITIVE_INFINITY);
    expect(rttSortKey(summary())).toBe(12_345_678);
  });

  it('lists pairing anomalies', () => {
    expect(transactionFlags(undefined)).toEqual([]);
    expect(transactionFlags(summary())).toEqual([]);
    expect(transactionFlags(summary({ unanswered: 2, unsolicited: 1, retransmissions: 4, late: 1 })))
      .toEqual(['2 unanswered', '1 unsolicited', '4 retransmitted', '1 late']);
  });
});
