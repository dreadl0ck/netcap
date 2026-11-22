import React, { useEffect, useState } from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { getLocale, initializeI18n, i18n, message, displayError, renderMessage, renderText, renderError, renderUIMessage, rawCode, setLocale, translate, useLocale, useTranslate, supportedLocales, resolveLocale, registerCatalogs, richText, artifactKindLabel, behaviorActionLabel, fieldLabel, suppliedMetadataText, type Catalogs } from '../i18n';
import { directCatalogBundle } from './direct';
import { formatBytes, formatDateTime, formatDurationNs, formatNumber, formatPercent, formatTimestampNs } from './format';
import { formatEvidenceJSON } from '../evidenceJSON';

afterEach(() => { cleanup(); setLocale('en'); });

test('synchronous offline initialization supports all locales, ICU plurals and exact source lookup', () => {
  expect(i18n.hasResourceBundle('en', 'direct')).toBe(false);
  for (const locale of supportedLocales) {
    initializeI18n({ locale });
    expect(getLocale()).toBe(locale);
    expect(translate('common.close')).not.toBe('common.close');
    expect(translate('Close')).toBe(translate('common.close'));
    expect(translate('packets.count', { count: 2 })).toContain('2');
  }
  setLocale('de');
  expect(translate('records.count', { count: 0 })).toBe('Keine Datensätze');
  expect(translate('packets.count', { count: 1 })).toBe('1 Paket');
  expect(translate('packets.count', { count: 2 })).toBe('2 Pakete');
  expect(() => translate('ui:no_such_key')).toThrow('Unknown message');
  expect(translate('Unmigrated source')).toBe('Unmigrated source');
  setLocale('en');
  expect(translate('time.epochNs', { value: 1700000000123456789n, time: 'UTC' })).toBe('1700000000123456789 ns (Unix; UTC)');
  expect(() => setLocale('xx' as 'en')).toThrow('Unsupported locale');
});

test('locale changes rerender consumers without unmounting or clearing component state', () => {
  const mounted = vi.fn();
  const unmounted = vi.fn();
  function Panel() {
    const t = useTranslate();
    const locale = useLocale();
    const [value, setValue] = useState('');
    const [notice] = useState(() => message('common.copy'));
    useEffect(() => { mounted(); return unmounted; }, []);
    return <><input aria-label="evidence" value={value} onChange={event => setValue(event.target.value)} /><button>{t('common.close')}</button><output>{locale}</output><span>{renderMessage(notice)}</span></>;
  }
  render(<Panel />);
  const input = screen.getByRole('textbox');
  fireEvent.change(input, { target: { value: 'User evidence TCP port 443' } });
  act(() => setLocale('zh-Hans'));
  expect(screen.getByRole('button').textContent).toBe('关闭');
  expect(screen.getByText('复制')).toBeTruthy();
  expect((input as HTMLInputElement).value).toBe('User evidence TCP port 443');
  expect(mounted).toHaveBeenCalledTimes(1);
  expect(unmounted).not.toHaveBeenCalled();
});

test('edition catalogs are explicitly registered and never transitively loaded by base entry', () => {
  initializeI18n({ locale: 'de', bundles: [directCatalogBundle] });
  expect(translate('direct:license.key')).toBe('Lizenzschlüssel');
  expect(translate('direct:license.trialStarted', { count: 1 })).toContain('1 Tag');
  expect(() => initializeI18n({ bundles: [{ ...directCatalogBundle, catalogs: { ...directCatalogBundle.catalogs, nl: {} } }] })).toThrow('Incomplete');
});

test('OS locale resolution handles region/script tags without silently replacing Traditional Chinese', () => {
  expect(resolveLocale('de-CH')).toBe('de');
  expect(resolveLocale('zh_Hans_CN')).toBe('zh-Hans');
  expect(resolveLocale(' zh_CN.UTF-8 ')).toBe('zh-Hans');
  expect(resolveLocale(['zh-Hant-TW', 'nl-BE'])).toBe('nl');
  expect(resolveLocale('zh-TW')).toBe('en');
});

test('structured backend message IDs can resolve locally while unknown backend text is preserved', () => {
  setLocale('de');
  expect(renderUIMessage({ id: 'common.close', text: 'Close' })).toBe('Schließen');
  expect(renderUIMessage({ id: 'webui.server_message', text: 'Close' })).toBe('Close');
  expect(renderUIMessage({ id: 'webui.raw_diagnostic', text: 'User evidence TCP port 443' })).toBe('User evidence TCP port 443');
});

test('open deferred messages change language while captured text and native diagnostics stay raw', () => {
  const pending = message('errors.withDetail', { message: message('common.copy'), detail: 'Close; SrcIP == 443' });
  setLocale('de');
  expect(renderText(pending)).toBe('Kopieren: Close; SrcIP == 443');
  expect(renderText('Close')).toBe('Close');
  expect(renderError({ message: 'Close' })).toBe('Close');
  expect(renderError({ cause: { messageI18n: { id: 'common.copy', text: 'Copy' } }, message: 'raw SDK diagnostic' })).toBe('Kopieren');
  const deferredError = displayError(message('errors.withDetail', { message: message('common.copy'), detail: 'Close; SrcIP == 443' }));
  expect(deferredError.message).toBe('Copy: Close; SrcIP == 443');
  expect(renderError(deferredError)).toBe('Kopieren: Close; SrcIP == 443');
  setLocale('zh-Hans');
  expect(renderText(pending)).toBe('复制：Close; SrcIP == 443');
  expect(rawCode('DstPort == {port}', { port: 12345 })).toBe('DstPort == 12345');
  expect(rawCode('Packet #{id}', { id: 1700000000123456789n })).toBe('Packet #1700000000123456789');
});

test('display formatters use explicit units/locales and retain bigint nanosecond precision', () => {
  expect(formatNumber(1234567.89, {}, 'de')).toBe('1.234.567,89');
  expect(formatPercent(25, 'percent', 'en')).toBe('25%');
  expect(formatPercent(0.25, 'ratio', 'en')).toBe('25%');
  expect(formatDurationNs('1234567', 'de')).toBe('1,235\u00a0ms');
  expect(formatBytes('1536', 'de')).toBe('1,5\u00a0KiB');
  expect(formatDurationNs('9007199254740993123456789', 'en')).toBe('104,249,991,374.317\u00a0d');
  const timestamp = formatTimestampNs('1700000000123456789', {}, 'en');
  expect(timestamp).toContain('123456789');
  expect(timestamp).toContain('UTC');
  expect(formatTimestampNs('-1', {}, 'en')).toContain('999999999');
  expect(() => formatTimestampNs('1700000000123456789.5')).toThrow();
  expect(() => formatTimestampNs(1700000000123456789 as unknown as string)).toThrow('bigint');
  expect(() => formatTimestampNs('99999999999999999999999999999')).toThrow('Date range');
  expect(formatDateTime(1700000000, 'seconds', {}, 'en')).toBe(formatDateTime(1700000000000, 'milliseconds', {}, 'en'));
});

test('evidence JSON retains original nanoseconds, numeric IDs, exponent spelling and strings in every locale', () => {
  const raw = '{"Timestamp":1700000000123456789,"id":900719925474099312345,"amount":-0.0000e+04,"text":"Close; SrcIP == 443","nested":[{},[],"{\\\"PCAP\\\"}"]}';
  for (const locale of supportedLocales) {
    setLocale(locale);
    const formatted = formatEvidenceJSON(raw);
    expect(formatted).toContain('1700000000123456789');
    expect(formatted).toContain('900719925474099312345');
    expect(formatted).toContain('-0.0000e+04');
    expect(formatted).toContain('"Close; SrcIP == 443"');
    expect(formatted).toContain('"{\\\"PCAP\\\"}"');
    expect(JSON.parse(formatted)).toEqual(JSON.parse(raw));
  }
  expect(formatEvidenceJSON('raw diagnostic PCAP')).toBe('raw diagnostic PCAP');
});

test('known metadata labels localize while custom schema fields, names and action IDs remain raw', () => {
  const user = { name: 'Close', description: 'Copy', kind: 'custom-user-kind' };
  for (const locale of supportedLocales) {
    setLocale(locale);
    expect(suppliedMetadataText(user, 'name')).toBe('Close');
    expect(suppliedMetadataText(user, 'description')).toBe('Copy');
    expect(artifactKindLabel(user.kind)).toBe('custom-user-kind');
    expect(artifactKindLabel('constructor')).toBe('constructor');
    expect(behaviorActionLabel('custom-user-action')).toBe('custom-user-action');
    expect(fieldLabel('SrcIP', 'CustomSchema')).toBe('SrcIP');
    expect(artifactKindLabel('proxy-nat-log')).not.toBe('proxy-nat-log');
  }
});

test('rich-text tag reordering keeps an interactive child mounted with its unsaved value', () => {
  const english = { 'test.richEditor': '<editor>Filter</editor> after' };
  const moved = { 'test.richEditor': 'before <editor>Filter</editor>' };
  const catalogs: Catalogs = { en: english, de: moved, nl: moved, fr: moved, es: moved, 'zh-Hans': moved };
  registerCatalogs({ namespace: 'ui', catalogs });
  function Panel() { useLocale(); return <div>{richText('ui:test.richEditor', { editor: () => <input aria-label="canonical-filter" defaultValue="tcp port 443" /> })}</div>; }
  render(<Panel />);
  const input = screen.getByRole('textbox');
  fireEvent.change(input, { target: { value: 'host 192.0.2.1 and port 12345' } });
  act(() => setLocale('de'));
  expect(screen.getByRole('textbox')).toBe(input);
  expect((input as HTMLInputElement).value).toBe('host 192.0.2.1 and port 12345');
});
