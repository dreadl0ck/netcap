import { useCallback, useSyncExternalStore } from 'react';
import { getLocale, getLocaleRevision, subscribeLocale, translate } from './i18n/runtime';

export * from './i18n/runtime';
export * from './i18n/locales';
export * from './i18n/format';
export * from './i18n/rich';
export * from './i18n/swr';
export * from './i18n/labels';
export * from './i18n/code';
export { formatEvidenceJSON } from './evidenceJSON';

export function useLocale() {
  useSyncExternalStore(subscribeLocale, getLocaleRevision, getLocaleRevision);
  return getLocale();
}

/** Its identity changes with locale, so [t] also invalidates memoized metadata. */
export function useTranslate(): typeof translate {
  const locale = useLocale();
  return useCallback<typeof translate>((sourceOrKey, params) => translate(sourceOrKey, params), [locale]);
}
