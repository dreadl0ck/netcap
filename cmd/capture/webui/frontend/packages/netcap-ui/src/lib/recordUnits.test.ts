import { describe, expect, it } from 'vitest';
import { formatRecordUnits } from './recordUnits';

describe('audit record units', () => {
  it('preserves large counters, identifiers, durations and protocol clock values', () => {
    const record = { Bytes: '1700000000000000001', SequenceNumber: 1700000000,
      ResponseTime: '1700000000000', ReferenceTimestamp: '1700000000000000000',
      Nested: [{ LeaseTime: 1700000000, ID: '1700000000000' }] };
    expect(formatRecordUnits(record)).toEqual(record);
  });
  it('uses declared nanoseconds for early captures and retains the exact raw value', () => {
    expect(formatRecordUnits({ Timestamp: '1000000001' })).toEqual({
      Timestamp: '1000000001 ns (Unix; 1970-01-01T00:00:01.000Z)',
    });
    expect(formatRecordUnits({ Timestamp: '1700000000123456789' })).toEqual({
      Timestamp: '1700000000123456789 ns (Unix; 2023-11-14T22:13:20.123Z)',
    });
  });
  it('does not invent precision or format unknown/default/invalid fields', () => {
    const record = { Timestamp: 1700000000123456789, TimestampLast: '0',
      TimestampFirst: 'invalid', Time: '1700000000000000000',
      NotBefore: '999999999999999999999999999999' };
    expect(formatRecordUnits(record)).toEqual(record);
  });
  it('formats nested declared fields without mutating the source', () => {
    const record = { Records: [{ Timestamp: '1000000000', Size: '1000000000' }] };
    expect(formatRecordUnits(record)).toEqual({ Records: [{
      Timestamp: '1000000000 ns (Unix; 1970-01-01T00:00:01.000Z)', Size: '1000000000',
    }] });
    expect(record.Records[0].Timestamp).toBe('1000000000');
    expect(formatRecordUnits('-1', 'Timestamp')).toBe('-1 ns (Unix; 1969-12-31T23:59:59.999Z)');
  });
});
