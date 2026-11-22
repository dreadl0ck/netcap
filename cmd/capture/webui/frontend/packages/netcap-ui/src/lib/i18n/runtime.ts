import { createInstance, type i18n as I18nInstance } from 'i18next';
import ICU from 'i18next-icu';
import { initReactI18next } from 'react-i18next';
import { uiCatalogs } from './catalogs/ui/bundle';
import uiSources from './catalogs/ui/sources.json';
import { isLocale, supportedLocales, type Locale } from './locales';
import { messageValues } from './values';
import backendIDs from './backend-ids.json';

export type MessageParams = Readonly<Record<string, unknown>>;
export type Catalogs = Readonly<Record<Locale, Readonly<Record<string, string>>>>;
export interface CatalogBundle { namespace: 'ui' | 'direct' | 'removed'; catalogs: Catalogs; sources?: Readonly<Record<string, string>> }
export interface Message { readonly key: string; readonly params?: MessageParams }
export interface JoinedMessage { readonly parts: readonly MessageText[]; readonly separator: string }
export type MessageText = string | Message | UIMessage | JoinedMessage;
/** Matches cmd/capture/webui/presentation.go's UIMessage wire shape. */
export interface UIMessage { readonly id: string; readonly params?: MessageParams; readonly text: string; readonly source?: string }

export const i18n: I18nInstance = createInstance();
const sourceKeys = new Map<string, string>();
const sourceExact = new Set<string>();
const keys = new Set<string>();
function explicitKey(key: string): string | undefined {
  const alias = (backendIDs as Record<string, string>)[key];
  return keys.has(key) ? key : keys.has(`ui:${key}`) ? `ui:${key}` : alias && keys.has(alias) ? alias : undefined;
}
const listeners = new Set<() => void>();
const descriptor = Symbol('netcap.ui.message');
function trusted<T extends object>(value: T): T { Object.defineProperty(value, descriptor, { value: true }); return value; }
export function resolveMessageValue(value: unknown): unknown {
  if (value instanceof Error) return renderError(value);
  if (value && typeof value === 'object' && (value as Record<symbol, unknown>)[descriptor]) return renderText(value as MessageText);
  return value;
}
let revision = 0;

function changed() {
  revision += 1;
  for (const listener of listeners) listener();
}

export function getLocale(): Locale {
  return isLocale(i18n.language) ? i18n.language : 'en';
}

export function subscribeLocale(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export function getLocaleRevision(): number { return revision; }

/** Complete offline bundles only. No loader, detector, browser storage or HTTP. */
export function registerCatalogs({ namespace, catalogs, sources = {} }: CatalogBundle): void {
  const englishKeys = Object.keys(catalogs.en).sort();
  for (const locale of supportedLocales) {
    const catalog = catalogs[locale];
    if (!catalog || Object.keys(catalog).sort().join('\0') !== englishKeys.join('\0')) {
      throw new Error(`Incomplete ${namespace} catalog: ${locale}`);
    }
    for (const key of englishKeys) {
      if (typeof catalog[key] !== 'string' || !catalog[key].trim()) throw new Error(`Empty message: ${locale}/${key}`);
      if (i18n.hasResourceBundle(locale, namespace)) {
        const existing = i18n.getResource(locale, namespace, key);
        if (existing !== undefined && existing !== catalog[key]) throw new Error(`Conflicting catalog key: ${namespace}:${key}`);
      }
    }
  }
  for (const locale of supportedLocales) i18n.addResourceBundle(locale, namespace, catalogs[locale], true, false);
  for (const [key, english] of Object.entries(catalogs.en)) {
    const qualified = `${namespace}:${key}`;
    keys.add(qualified);
    // Shared messages win over an optional edition bundle's duplicate wording.
    for (const source of new Set([english, sources[key] ?? english])) {
      const current = sourceKeys.get(source);
      const exact = source === english;
      // A plain source must not resolve to a rich-text alias such as <tag0>Harvesters</tag0>.
      const currentExact = current !== undefined && sourceExact.has(`${current}\0${source}`);
      if (exact) sourceExact.add(`${qualified}\0${source}`);
      if (current === undefined || (exact && !currentExact) || (exact === currentExact && namespace === 'ui' && !current.startsWith('ui:'))) sourceKeys.set(source, qualified);
    }
  }
  changed();
}

i18n.use(ICU).use(initReactI18next);
void i18n.init({
  lng: 'en',
  supportedLngs: [...supportedLocales],
  fallbackLng: false,
  load: 'currentOnly',
  ns: ['ui'],
  defaultNS: 'ui',
  resources: {},
  initAsync: false,
  keySeparator: false,
  interpolation: { escapeValue: false },
  react: { useSuspense: false },
  i18nFormat: { parseErrorHandler: (error: Error) => { throw error; } },
});
i18n.on('languageChanged', changed);
registerCatalogs({ namespace: 'ui', catalogs: uiCatalogs, sources: uiSources });

/** Host calls this synchronously before createRoot(...).render(...). */
export function initializeI18n(options: { locale?: Locale; bundles?: readonly CatalogBundle[] } = {}): I18nInstance {
  for (const bundle of options.bundles ?? []) registerCatalogs(bundle);
  if (options.locale) setLocale(options.locale);
  return i18n;
}

export function setLocale(locale: Locale): void {
  if (!isLocale(locale)) throw new RangeError(`Unsupported locale: ${locale}`);
  // All resources are present: i18next changes language and emits synchronously.
  void i18n.changeLanguage(locale);
}

/** Never call this on captured/user/API text. Source lookup is exact, not fuzzy. */
export function translate(sourceOrKey: string | null | undefined, params?: MessageParams): string {
  if (sourceOrKey == null) return '';
  const key = explicitKey(sourceOrKey) ?? sourceKeys.get(sourceOrKey);
  if (!key) {
    if (/^(?:ui|direct|removed):/.test(sourceOrKey)) throw new Error(`Unknown message key: ${sourceOrKey}`);
    return sourceOrKey; // Incremental source migration; the source checker gates completion.
  }
  const values = Object.fromEntries(Object.entries(params ?? {}).map(([name, raw]) => {
    const value = resolveMessageValue(raw);
    return [name, value == null ? '' : ['string', 'number', 'bigint', 'boolean'].includes(typeof value) || value instanceof Date ? value : String(value)];
  }));
  if (key === 'ui:time.epochNs' && values.value !== undefined) values.value = String(values.value);
  const colon = key.indexOf(':');
  const pattern = i18n.getResource('en', key.slice(0, colon), key.slice(colon + 1));
  const result = i18n.t(key, messageValues(pattern, values, getLocale()));
  if (typeof result !== 'string') throw new Error(`Message is not text: ${key}`);
  return result;
}

/** Store descriptors, not translated strings, in state and module-level metadata. */
export function message(key: string, params?: MessageParams): Message { return trusted({ key, params }); }
export function renderMessage(value: Message): string { return translate(value.key, value.params); }

export function hasCatalogKey(key: string): boolean { return explicitKey(key) !== undefined; }
export function hasCatalogSource(source: string): boolean { return sourceKeys.has(source); }

export function catalogPattern(sourceOrKey: string): string {
  const key = explicitKey(sourceOrKey) ?? sourceKeys.get(sourceOrKey);
  if (!key) throw new Error(`Unknown message: ${sourceOrKey}`);
  const colon = key.indexOf(':');
  return i18n.getResource(getLocale(), key.slice(0, colon), key.slice(colon + 1));
}

export function renderText(value: MessageText | null | undefined): string {
  if (value == null) return '';
  return typeof value === 'string' ? value : 'parts' in value ? value.parts.map(renderText).join(value.separator) : 'key' in value ? renderMessage(value) : renderUIMessage(value);
}

export function messageSource(value: MessageText): string {
  if (typeof value === 'string') return value;
  if ('parts' in value) return value.parts.map(messageSource).join(value.separator);
  if ('id' in value) return value.text;
  const key = explicitKey(value.key) ?? sourceKeys.get(value.key);
  if (!key) return value.key;
  const colon = key.indexOf(':'), pattern = i18n.getResource('en', key.slice(0, colon), key.slice(colon + 1));
  const params = Object.fromEntries(Object.entries(value.params ?? {}).map(([name, item]) => [name,
    item && typeof item === 'object' && (item as Record<symbol, unknown>)[descriptor] ? messageSource(item as MessageText) : item instanceof Error ? item.message : item,
  ]));
  if (key === 'ui:time.epochNs' && params.value !== undefined) params.value = String(params.value);
  return i18n.t(key, { ...messageValues(pattern, params, 'en'), lng: 'en' });
}

class PresentationError extends Error {
  constructor(readonly presentation: MessageText, options?: ErrorOptions) { super(messageSource(presentation), options); }
}
export function displayError(value: MessageText, options?: ErrorOptions): Error { return new PresentationError(value, options); }
export function errorText(value: unknown): MessageText {
  if (value instanceof PresentationError) return value.presentation;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (record.presentation && typeof record.presentation === 'object' && (record.presentation as Record<symbol, unknown>)[descriptor]) return record.presentation as MessageText;
    const cause = record.cause && typeof record.cause === 'object' ? record.cause as Record<string, unknown> : undefined;
    const presentation = record.messageI18n ?? cause?.messageI18n;
    if (presentation && typeof presentation === 'object' && typeof (presentation as UIMessage).id === 'string' && typeof (presentation as UIMessage).text === 'string') return trusted({ ...presentation as UIMessage });
    if (typeof record.message === 'string') return record.message;
  }
  return value instanceof Error ? value.message : String(value);
}
export function renderError(value: unknown): string { return renderText(errorText(value)); }
export function errorDiagnostic(value: unknown): string {
  const lines: string[] = [], seen = new Set<unknown>();
  function collect(error: unknown) {
    if (!error || typeof error !== 'object' || seen.has(error)) return;
    seen.add(error);
    const record = error as Record<string, unknown>;
    for (const field of ['message', 'diagnostic']) if (typeof record[field] === 'string' && record[field] && !lines.includes(record[field])) lines.push(record[field]);
    collect(record.cause);
  }
  collect(value);
  return lines.length ? lines.join('\n') : String(value);
}
export function joinMessages(parts: readonly MessageText[], separator = '\n'): JoinedMessage { return trusted({ parts, separator }); }

/** Backend text is already resolved for its request's locale; never source-match it. */
export function renderUIMessage(value: UIMessage | null | undefined, legacy = ''): string {
  if (value) return hasCatalogKey(value.id) ? translate(value.id, value.params) : value.id !== 'chart.field.description' && value.source && hasCatalogSource(value.source) ? translate(value.source, value.params) : value.text;
  return hasCatalogSource(legacy) ? translate(legacy) : legacy;
}

/** Call only for backend-authored presentation fields, never evidence/user fields. */
export function metadataText(owner: unknown, field: string, fallback?: string): string {
  if (!owner || typeof owner !== 'object') return fallback ?? '';
  const record = owner as Record<string, unknown>;
  const localized = record[`${field}I18n`];
  const legacy = typeof record[field] === 'string' ? record[field] as string : fallback ?? '';
  if (localized && typeof localized === 'object' && typeof (localized as UIMessage).id === 'string' && typeof (localized as UIMessage).text === 'string') return renderUIMessage({ ...localized as UIMessage, source: legacy }, legacy);
  return hasCatalogSource(legacy) ? translate(legacy) : legacy;
}

export function metadataMessage(owner: unknown, field: string): MessageText {
  if (!owner || typeof owner !== 'object') return '';
  const record = owner as Record<string, unknown>;
  const localized = record[`${field}I18n`];
  const source = typeof record[field] === 'string' ? record[field] as string : '';
  if (localized && typeof localized === 'object' && typeof (localized as UIMessage).id === 'string' && typeof (localized as UIMessage).text === 'string') return trusted({ ...localized as UIMessage, source });
  return hasCatalogSource(source) ? message(source) : source;
}

export function presentationValue(owner: unknown, field: string): UIMessage | undefined {
  if (!owner || typeof owner !== 'object') return undefined;
  const record = owner as Record<string, unknown>, value = record[`${field}I18n`];
  return value && typeof value === 'object' && typeof (value as UIMessage).id === 'string' && typeof (value as UIMessage).text === 'string' ? trusted({ ...value as UIMessage, source: typeof record[field] === 'string' ? record[field] as string : undefined }) : undefined;
}

export function suppliedMetadataText(owner: unknown, field: string): string {
  if (!owner || typeof owner !== 'object') return '';
  const record = owner as Record<string, unknown>, value = record[`${field}I18n`];
  if (value && typeof value === 'object' && typeof (value as UIMessage).id === 'string' && typeof (value as UIMessage).text === 'string') return renderUIMessage({ ...value as UIMessage, source: typeof record[field] === 'string' ? record[field] as string : undefined });
  return String(record[field] ?? '');
}

export function metadataMessages(owner: unknown, field: string): MessageText[] {
  if (!owner || typeof owner !== 'object') return [];
  const record = owner as Record<string, unknown>, source = record[field], values = record[`${field}I18n`];
  if (Array.isArray(values) && values.length) return Array.from({ length: Math.max(values.length, Array.isArray(source) ? source.length : 0) }, (_, index) => {
    const value = values[index];
    return value && typeof value === 'object' && typeof value.id === 'string' && typeof value.text === 'string' ? trusted({ ...value, source: Array.isArray(source) && typeof source[index] === 'string' ? source[index] : undefined }) : Array.isArray(source) ? String(source[index] ?? '') : '';
  });
  return Array.isArray(source) ? source.map(value => String(value)) : [];
}
export function metadataTexts(owner: unknown, field: string): string[] { return metadataMessages(owner, field).map(renderText); }

export function localeURL(input: string): string {
  const hashAt = input.indexOf('#');
  const hash = hashAt === -1 ? '' : input.slice(hashAt);
  const base = hashAt === -1 ? input : input.slice(0, hashAt);
  const queryAt = base.indexOf('?');
  const pathname = queryAt === -1 ? base : base.slice(0, queryAt);
  const query = new URLSearchParams(queryAt === -1 ? '' : base.slice(queryAt + 1));
  query.set('locale', getLocale());
  return `${pathname}?${query}${hash}`;
}
