import { getLocale } from './runtime';
import type { Locale } from './locales';

export type ExactInteger = bigint | string;
export type DisplayUnit = 'ns' | 'µs' | 'ms' | 's' | 'min' | 'h' | 'd' | 'B' | 'KiB' | 'MiB' | 'GiB' | 'TiB' | 'bit/s' | 'kbit/s' | 'Mbit/s' | 'Gbit/s';

function integer(value: ExactInteger): bigint {
  if (typeof value !== 'bigint' && typeof value !== 'string') throw new TypeError('Exact values require bigint or an integer string');
  if (typeof value === 'string' && !/^-?\d+$/.test(value)) throw new RangeError('Expected an exact integer string');
  return BigInt(value);
}

export function formatNumber(value: number | bigint, options: Intl.NumberFormatOptions = {}, locale: Locale = getLocale()): string {
  if (typeof value === 'number' && !Number.isFinite(value)) throw new RangeError('Expected a finite display value');
  return new Intl.NumberFormat(locale, options).format(value);
}

export function formatPercent(value: number, input: 'ratio' | 'percent', locale: Locale = getLocale()): string {
  return formatNumber(input === 'ratio' ? value : value / 100, { style: 'percent', maximumFractionDigits: 2 }, locale);
}

export function formatQuantity(value: number | bigint, unit: DisplayUnit, locale: Locale = getLocale()): string {
  return `${formatNumber(value, { maximumFractionDigits: 3 }, locale)}\u00a0${unit}`;
}

/** Round the fraction using integer arithmetic; even petabyte counters stay exact. */
function formatRatio(numerator: bigint, denominator: bigint, digits: number, locale: Locale): string {
  const negative = numerator < 0n;
  const magnitude = negative ? -numerator : numerator;
  const scale = 10n ** BigInt(digits);
  const scaled = (magnitude * scale + denominator / 2n) / denominator;
  const whole = scaled / scale;
  const fraction = String(scaled % scale).padStart(digits, '0').replace(/0+$/, '');
  const numberFormat = new Intl.NumberFormat(locale);
  const decimal = numberFormat.formatToParts(1.1).find(part => part.type === 'decimal')?.value ?? '.';
  const minus = numberFormat.formatToParts(-1).find(part => part.type === 'minusSign')?.value ?? '-';
  return `${negative ? minus : ''}${numberFormat.format(whole)}${fraction ? decimal + fraction : ''}`;
}

/** Units are explicit, with no magnitude-based guessing of the input unit. */
export function formatDurationNs(value: ExactInteger, locale: Locale = getLocale()): string {
  const ns = integer(value);
  const magnitude = ns < 0n ? -ns : ns;
  const units: readonly [bigint, DisplayUnit][] = [
    [86_400_000_000_000n, 'd'], [3_600_000_000_000n, 'h'], [60_000_000_000n, 'min'],
    [1_000_000_000n, 's'], [1_000_000n, 'ms'], [1_000n, 'µs'], [1n, 'ns'],
  ];
  const [divisor, unit] = units.find(([threshold]) => magnitude >= threshold) ?? units[units.length - 1];
  return `${formatRatio(ns, divisor, 3, locale)}\u00a0${unit}`;
}

export function formatBytes(value: ExactInteger, locale: Locale = getLocale()): string {
  const bytes = integer(value);
  const magnitude = bytes < 0n ? -bytes : bytes;
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'] as const;
  let exponent = 0;
  let divisor = 1n;
  while (magnitude >= divisor * 1024n && exponent < units.length - 1) { divisor *= 1024n; exponent += 1; }
  return `${formatRatio(bytes, divisor, 2, locale)}\u00a0${units[exponent]}`;
}

export interface TimestampOptions {
  /** Explicit IANA zone; UTC by default. Input is always Unix nanoseconds. */
  timeZone?: string;
  fractionalDigits?: 0 | 3 | 6 | 9;
}

function clockParts(value: ExactInteger) {
  const ns = integer(value);
  let milliseconds = ns / 1_000_000n, fraction = ns % 1_000_000_000n;
  if (ns < 0n && ns % 1_000_000n) milliseconds -= 1n;
  if (fraction < 0n) fraction += 1_000_000_000n;
  if (milliseconds < -8_640_000_000_000_000n || milliseconds > 8_640_000_000_000_000n) throw new RangeError('Timestamp outside the Date range');
  return { date: new Date(Number(milliseconds)), fraction: String(fraction).padStart(9, '0') };
}

export function formatClockNs(value: ExactInteger, timeZone: string, fractionalDigits: 0 | 3 | 6 | 9 = 9, locale: Locale = getLocale()): string {
  const { date, fraction } = clockParts(value);
  return new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZone, ...(fractionalDigits ? { fractionalSecondDigits: 3 as const } : {}) })
    .formatToParts(date).map(part => part.type === 'fractionalSecond' ? fraction.slice(0, fractionalDigits) : part.value).join('');
}

export function formatCalendarDateNs(value: ExactInteger, timeZone: string, locale: Locale = getLocale()): string {
  return new Intl.DateTimeFormat(locale, { year: 'numeric', month: '2-digit', day: '2-digit', timeZone }).format(clockParts(value).date);
}

export function formatTimestampNs(value: ExactInteger, options: TimestampOptions = {}, locale: Locale = getLocale()): string {
  const ns = integer(value);
  let seconds = ns / 1_000_000_000n;
  let fraction = ns % 1_000_000_000n;
  if (fraction < 0n) { seconds -= 1n; fraction += 1_000_000_000n; }
  const milliseconds = seconds * 1000n + fraction / 1_000_000n;
  if (milliseconds < -8_640_000_000_000_000n || milliseconds > 8_640_000_000_000_000n) throw new RangeError('Timestamp outside the Date range');
  const fractionalDigits = options.fractionalDigits ?? 9;
  const formatter = new Intl.DateTimeFormat(locale, {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    hourCycle: 'h23', timeZone: options.timeZone ?? 'UTC', timeZoneName: 'short',
    ...(fractionalDigits ? { fractionalSecondDigits: 3 as const } : {}),
  });
  // Date only sees an exactly representable millisecond; the nine-digit fraction
  // comes from the original bigint, including timestamps before the Unix epoch.
  return formatter.formatToParts(new Date(Number(milliseconds))).map(part =>
    part.type === 'fractionalSecond' ? String(fraction).padStart(9, '0').slice(0, fractionalDigits) : part.value,
  ).join('');
}

/** For API fields documented as seconds or milliseconds, never infer by size. */
export function formatDateTime(value: Date | number, inputUnit: 'milliseconds' | 'seconds', options: Intl.DateTimeFormatOptions = {}, locale: Locale = getLocale()): string {
  const date = value instanceof Date ? value : new Date(inputUnit === 'seconds' ? value * 1000 : value);
  if (!Number.isFinite(date.getTime())) throw new RangeError('Invalid display date');
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'long', timeZone: 'UTC', ...options }).format(date);
}

export function formatRelativeTime(value: number, unit: Intl.RelativeTimeFormatUnit, locale: Locale = getLocale()): string {
  return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(value, unit);
}

export function formatList(values: readonly string[], locale: Locale = getLocale()): string {
  return new Intl.ListFormat(locale, { style: 'long', type: 'conjunction' }).format(values);
}
