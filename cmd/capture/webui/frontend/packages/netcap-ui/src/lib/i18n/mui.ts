import { enUS, deDE, nlNL, frFR, esES, zhCN } from '@mui/material/locale';
import { getLocale, translate } from './runtime';
import type { Locale } from './locales';

const muiLocales = { en: enUS, de: deDE, nl: nlNL, fr: frFR, es: esES, 'zh-Hans': zhCN };
export function getMuiLocale(locale: Locale = getLocale()) { return muiLocales[locale]; }

export function paginationLabel({ from, to, count }: { from: number; to: number; count: number }): string {
  return translate(count === -1 ? 'table.pageRangeUnknown' : 'table.pageRange', { from, to, count });
}
