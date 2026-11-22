import { IntlMessageFormat } from 'intl-messageformat';
import type { Locale } from './locales';

const kinds = new Map<string, Set<string>>();
/** Bare numeric UI parameters use the selected locale; typed ICU arguments stay numeric. */
export function messageValues(pattern: string, values: Readonly<Record<string, unknown>>, locale: Locale, react = false): Record<string, unknown> {
  let typed = kinds.get(pattern);
  if (!typed) {
    typed = new Set();
    function walk(elements: readonly any[]) {
      for (const element of elements) {
        if ([2, 3, 4, 5, 6].includes(element.type)) typed!.add(element.value);
        if (element.children) walk(element.children);
        if (element.options) Object.values(element.options).forEach((option: any) => walk(option.value));
      }
    }
    walk(new IntlMessageFormat(pattern, 'en').getAst()); kinds.set(pattern, typed);
  }
  const number = new Intl.NumberFormat(locale, { maximumFractionDigits: 6 });
  return Object.fromEntries(Object.entries(values).map(([name, value]) => [name,
    value == null ? '' : !typed!.has(name) && typeof value === 'boolean' ? react ? '' : String(value) : /^(?:id|ordinal|port|srcPort|dstPort|schema|sequence|statusCode|httpStatus|timestampNs|startNs|endNs|.*ID|.*Id)$/.test(name) && (typeof value === 'number' || typeof value === 'bigint') ? String(value) : !typed!.has(name) && (typeof value === 'number' || typeof value === 'bigint') ? number.format(value) : !typed!.has(name) && value instanceof Date ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'long', timeZone: 'UTC' }).format(value) : value,
  ]));
}
