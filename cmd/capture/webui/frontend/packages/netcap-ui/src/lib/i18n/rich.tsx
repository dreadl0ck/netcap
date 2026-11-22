import { Children, cloneElement, isValidElement, type ReactNode } from 'react';
import { IntlMessageFormat } from 'intl-messageformat';
import { catalogPattern, getLocale, resolveMessageValue } from './runtime';
import { messageValues } from './values';

type RichValue = ReactNode | ((children: ReactNode[]) => ReactNode);
const compiled = new Map<string, IntlMessageFormat>();

/** ICU named tags retain React elements; captured parameters stay text/nodes. */
export function richText(key: string, values: Record<string, unknown>): ReactNode {
  const locale = getLocale();
  const cacheKey = `${locale}:${key}`;
  let format = compiled.get(cacheKey);
  if (!format) {
    format = new IntlMessageFormat(catalogPattern(key), locale);
    compiled.set(cacheKey, format);
  }
  const keyed = (value: ReactNode, name: string) => isValidElement(value) ? cloneElement(value, { key: `${name}:${value.key ?? ''}` }) : value;
  const parameters = Object.fromEntries(Object.entries(values).map(([name, raw]) => {
    const value = resolveMessageValue(raw);
    return [name, typeof value === 'function' ? (chunks: ReactNode[]) => keyed(value(Children.toArray(chunks)), `tag:${name}`) : keyed(value as ReactNode, `arg:${name}`)];
  }));
  const result = format.format(messageValues(catalogPattern(key), parameters, locale, true) as Parameters<typeof format.format>[0]) as ReactNode;
  return Array.isArray(result) ? Children.toArray(result) : result;
}
