import useSWR, { mutate } from 'swr';
import { useLocale } from '../i18n';

/** Bundled metadata rerenders without replacing cached records or unsaved form state. */
export const usePresentationSWR: typeof useSWR = ((key: any, fetcher?: any, config?: any) => {
  useLocale();
  if (fetcher && typeof fetcher !== 'function') return useSWR(key, fetcher);
  return useSWR(key, fetcher, config);
}) as typeof useSWR;

export const mutatePresentation: typeof mutate = mutate;
