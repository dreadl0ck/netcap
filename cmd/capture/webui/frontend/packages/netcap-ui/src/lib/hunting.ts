/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

/** Observed client production versus consumption; null means no usable bytes. */
export function producerConsumerRatio(produced: number, consumed: number): number | null {
  if (![produced, consumed].every(n => Number.isFinite(n) && n >= 0) || produced + consumed === 0) return null;
  return (produced - consumed) / (produced + consumed);
}
