// Audit-record capture times are Unix nanoseconds, independent of magnitude.
const unixNanosecondFields = new Set([
  'Timestamp', 'TimestampFirst', 'TimestampLast', 'SynTimestamp', 'SynAckTimestamp',
  'ClientHelloTimestamp', 'ServerHelloTimestamp', 'RequestTimestamp',
  'NotBefore', 'NotAfter', 'DetectedAt',
]);

export function formatRecordUnits(value: unknown, field?: string): unknown {
  if (field && unixNanosecondFields.has(field) &&
      (typeof value === 'string' || typeof value === 'number')) {
    // An already rounded JSON number cannot provide exact evidence.
    if (typeof value === 'number' && !Number.isSafeInteger(value)) return value;
    const raw = String(value);
    if (!/^-?\d+$/.test(raw)) return value;
    try {
      const ns = BigInt(raw);
      if (ns === 0n) return value; // Common absent/default value.
      const ms = ns / 1_000_000n - (ns < 0n && ns % 1_000_000n !== 0n ? 1n : 0n);
      const date = new Date(Number(ms));
      if (!Number.isFinite(date.getTime())) return value;
      return `${raw} ns (Unix; ${date.toISOString()})`;
    } catch { return value; }
  }
  if (Array.isArray(value)) return value.map(item => formatRecordUnits(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, formatRecordUnits(item, key)]));
  }
  return value;
}
