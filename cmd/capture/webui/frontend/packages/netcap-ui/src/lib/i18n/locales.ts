export const locales = [
  { id: 'en', intl: 'en', name: 'English', direction: 'ltr' },
  { id: 'de', intl: 'de', name: 'Deutsch', direction: 'ltr' },
  { id: 'nl', intl: 'nl', name: 'Nederlands', direction: 'ltr' },
  { id: 'fr', intl: 'fr', name: 'Français', direction: 'ltr' },
  { id: 'es', intl: 'es', name: 'Español', direction: 'ltr' },
  { id: 'zh-Hans', intl: 'zh-Hans', name: '简体中文', direction: 'ltr' },
] as const;

export type Locale = typeof locales[number]['id'];
export const supportedLocales: readonly Locale[] = locales.map(locale => locale.id);

export function isLocale(value: unknown): value is Locale {
  return typeof value === 'string' && supportedLocales.includes(value as Locale);
}

/** Resolve OS/browser language tags once, before the host mounts React. */
export function resolveLocale(preferences: string | readonly string[] | undefined): Locale {
  for (const preference of typeof preferences === 'string' ? [preferences] : preferences ?? []) {
    const tag = preference.trim().replaceAll('_', '-').toLowerCase().split(/[.@]/)[0];
    const [language, ...subtags] = tag.split('-');
    if (language === 'zh' && !subtags.some(part => ['hant', 'tw', 'hk', 'mo'].includes(part))) return 'zh-Hans';
    if (language !== 'zh' && isLocale(language)) return language;
  }
  return 'en';
}

// JetBrains Mono and Space Grotesk do not contain Han glyphs. Keep CJK faces
// local/offline; the host applies this stack to prose, retaining mono for data.
export const chineseFontFallback = '"PingFang SC", "Microsoft YaHei", "Noto Sans CJK SC", "Noto Sans SC", sans-serif';
