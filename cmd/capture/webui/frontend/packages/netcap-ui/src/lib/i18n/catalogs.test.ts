import { expect, test } from 'vitest';
import { IntlMessageFormat } from 'intl-messageformat';
import { supportedLocales } from './locales';
import { uiCatalogs } from './catalogs/ui/bundle';
import { directCatalogBundle } from './direct';
import { removedCatalogBundle } from './removed';

test('every bundled message compiles and formats offline in the actual runtime formatter', () => {
  let rendered = 0;
  for (const catalogs of [uiCatalogs, directCatalogBundle.catalogs, removedCatalogBundle.catalogs]) for (const locale of supportedLocales) for (const [key, pattern] of Object.entries(catalogs[locale])) {
    const formatter = new IntlMessageFormat(pattern, locale), values: Record<string, any> = {};
    function parameters(elements: readonly any[]) {
      for (const item of elements) {
        if (item.type === 1) values[item.value] ??= 'RAW-PCAP-443';
        else if ([2, 6].includes(item.type)) values[item.value] = 2;
        else if ([3, 4].includes(item.type)) values[item.value] = new Date('2026-10-03T12:00:00Z');
        else if (item.type === 5) values[item.value] = Object.keys(item.options).find(key => key !== 'other') ?? 'other';
        else if (item.type === 8) values[item.value] = (chunks: string[]) => chunks.join('');
        if (item.children) parameters(item.children);
        if (item.options) Object.values(item.options).forEach((option: any) => parameters(option.value));
      }
    }
    parameters(formatter.getAst());
    expect(() => formatter.format(values), `${locale}/${key}`).not.toThrow();
    rendered++;
  }
  expect(rendered).toBeGreaterThan(43000);
}, 30000);
