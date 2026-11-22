import React from 'react';
import { afterAll, afterEach, beforeAll, expect, test, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import BPFPage from '../../pages/BPFPage';
import ConfigPage from '../../pages/ConfigPage';
import DecodersPage from '../../pages/DecodersPage';
import { metadataText, renderUIMessage, setLocale, supportedLocales, translate } from '../i18n';

const state = vi.hoisted(() => ({ filter: 'tcp port 443', get: vi.fn(), save: vi.fn(), config: vi.fn(), features: vi.fn(), feature: vi.fn(), decoders: vi.fn(), decoderConfig: vi.fn(), savedConfigs: vi.fn(), version: vi.fn(), fields: vi.fn(), load: vi.fn() }));
vi.mock('../../hooks/useNetcapApi', () => ({ useNetcapApi: () => ({ getBPFInfo: state.get, saveBPFConfig: state.save, getConfig: state.config, getFeatures: state.features, setFeature: state.feature, getDecoders: state.decoders, getDecoderConfig: state.decoderConfig, listDecoderConfigs: state.savedConfigs, getVersion: state.version, getAllDecoderFields: state.fields, loadDecoderConfig: state.load }) }));
vi.mock('../../components/Layout', () => ({ default: ({ children }: { children: React.ReactNode }) => <main>{children}</main> }));

afterEach(() => { cleanup(); setLocale('en'); vi.clearAllMocks(); });
const originalInnerText = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'innerText');
beforeAll(() => Object.defineProperty(HTMLElement.prototype, 'innerText', { configurable: true, get() { return this.textContent ?? ''; }, set(value: string) { this.textContent = value; } }));
afterAll(() => { if (originalInnerText) Object.defineProperty(HTMLElement.prototype, 'innerText', originalInnerText); else delete (HTMLElement.prototype as unknown as { innerText?: string }).innerText; });

test('BPF page keeps an unsaved canonical filter and deferred response across all six locales without refetching', async () => {
  state.filter = 'tcp port 443';
  state.get.mockImplementation(async () => ({ currentFilter: state.filter, docsUrl: 'https://www.tcpdump.org/manpages/pcap-filter.7.html', filters: [], examples: [] }));
  state.save.mockImplementation(async ({ filter }: { filter: string }) => {
    state.filter = filter;
    return { message: 'Copy', messageI18n: { id: 'common.copy', text: 'Copy' } };
  });
  const cache = new Map();
  render(<SWRConfig value={{ provider: () => cache, dedupingInterval: 0 }}><BPFPage /></SWRConfig>);
  const input = await screen.findByRole('textbox');
  await waitFor(() => expect(input.textContent).toBe('tcp port 443'));
  await act(async () => { fireEvent.input(input, { target: { innerText: 'tcp and dst port 443' } }); });
  fireEvent.click(screen.getByRole('button', { name: translate('ui:m_cceb1f9ea725d00261ba') }));
  await screen.findByText(translate('common.copy'));
  await waitFor(() => expect(state.get).toHaveBeenCalledTimes(2));
  await act(async () => { fireEvent.input(input, { target: { innerText: 'host 192.0.2.1 and tcp port 12345' } }); });
  const requests = state.get.mock.calls.length;
  for (const locale of supportedLocales) {
    act(() => setLocale(locale));
    expect(screen.getByRole('textbox')).toBe(input);
    expect(input.textContent).toBe('host 192.0.2.1 and tcp port 12345');
    expect(screen.getByRole('textbox', { name: translate('ui:m_3057da6e637180a241fd') })).toBe(input);
    expect(input.getAttribute('data-learn')).toBe(translate('ui:m_e4a5dbd178398b78b7b1'));
    expect(screen.getByRole('button', { name: translate('ui:m_cceb1f9ea725d00261ba') })).toBeTruthy();
    expect(screen.getByText(translate('common.copy'))).toBeTruthy();
  }
  expect(state.get).toHaveBeenCalledTimes(requests);
  expect(state.save).toHaveBeenCalledTimes(1);
});

test('cached config and feature metadata switches language while search, CLI names, values and failed-toggle messages retain their identity', async () => {
  const option = { name: 'input', value: '/captures/Close.pcap', default: '', type: 'string', category: 'Input/Output', description: 'cached English description', isEditable: false, labelI18n: { id: 'config.option.input.label', text: 'Input file' }, descriptionI18n: { id: 'config.option.input.description', text: 'cached English description' }, categoryI18n: { id: 'config.category.input-output', text: 'Input/Output' } };
  const feature = { name: 'dns-resolution-context', title: 'cached English title', description: 'cached English description', enabled: false, scope: 'query', flag: '-dns-resolution-context', env: 'NETCAP_DNS_CONTEXT', titleI18n: { id: 'feature.dns-resolution-context.title', text: 'cached English title' }, descriptionI18n: { id: 'feature.dns-resolution-context.description', text: 'cached English description' }, scopeI18n: { id: 'feature.scope.query', text: 'Next API request' } };
  const failure = { id: 'feature.unknown', text: 'Unknown feature', params: { name: 'RAW_feature_12345' } };
  const custom = { ...option, name: 'Close', labelI18n: undefined, value: 'RAW_CUSTOM_CLI_VALUE' };
  state.config.mockResolvedValue({ readOnly: true, options: [option, custom] });
  state.features.mockResolvedValue({ features: [feature] });
  state.feature.mockRejectedValue({ message: 'RAW backend detail', messageI18n: failure });
  render(<SWRConfig value={{ provider: () => new Map() }}><ConfigPage /></SWRConfig>);
  await screen.findByText('/captures/Close.pcap');
  for (const locale of supportedLocales) {
    act(() => setLocale(locale));
    expect(screen.getByText(renderUIMessage(option.labelI18n))).toBeTruthy();
    expect(screen.getAllByText(renderUIMessage(option.descriptionI18n)).length).toBe(2);
    expect(screen.getByText(renderUIMessage(option.categoryI18n))).toBeTruthy();
    expect(screen.getByText(renderUIMessage(feature.scopeI18n))).toBeTruthy();
    expect(screen.getByText('input', { exact: true })).toBeTruthy();
    expect(screen.getAllByText('Close', { exact: true })).toHaveLength(2);
    expect(screen.getByText('RAW_CUSTOM_CLI_VALUE')).toBeTruthy();
    expect(screen.getByText('/captures/Close.pcap')).toBeTruthy();
    const search = screen.getByRole('textbox', { name: translate('ui:m_588eb6ab1c7da1684c83') });
    fireEvent.change(search, { target: { value: metadataText(option, 'label') } });
    expect(screen.getByText('/captures/Close.pcap')).toBeTruthy();
    fireEvent.change(search, { target: { value: '' } });
  }
  fireEvent.click(screen.getByLabelText(renderUIMessage(feature.titleI18n)));
  const alert = await screen.findByRole('alert');
  for (const locale of supportedLocales) {
    act(() => setLocale(locale));
    expect(alert.textContent).toContain(renderUIMessage(failure));
    expect(alert.textContent).not.toContain('[object Object]');
  }
  expect(state.feature).toHaveBeenCalledExactlyOnceWith('dns-resolution-context', true);
  expect(state.config).toHaveBeenCalledTimes(1);
  expect(state.features).toHaveBeenCalledTimes(1);
  expect(option.value).toBe('/captures/Close.pcap');
  expect(feature.enabled).toBe(false);
});

test('loading a decoder preset composes its deferred success with the raw warning instead of coercing metadata', async () => {
  state.decoders.mockResolvedValue({ packet: [], gopacket: [], stream: [], abstract: [] });
  state.decoderConfig.mockResolvedValue({ includeDecoders: '', excludeDecoders: '', enabledDecoders: [] });
  state.savedConfigs.mockResolvedValue([{ name: 'Close', path: '/configs/Close.json', modifiedTime: 1700000000, size: 10 }]);
  state.version.mockResolvedValue({ version: '99.0.0-fixture', commit: 'local' });
  state.fields.mockResolvedValue({});
  state.load.mockResolvedValue({ message: 'Copy', messageI18n: { id: 'common.copy', text: 'Copy' }, warning: 'RAW warning Close 12345' });
  render(<SWRConfig value={{ provider: () => new Map() }}><DecodersPage /></SWRConfig>);
  fireEvent.click(await screen.findByRole('button', { name: translate('ui:m_1b14081bb43e75a26c36') }));
  await screen.findByText('Close', { exact: true });
  fireEvent.click(screen.getByRole('button', { name: translate('ui:m_edf4fc6d7b5f54a5c144') }));
  const success = await screen.findByRole('alert');
  for (const locale of supportedLocales) {
    act(() => setLocale(locale));
    expect(success.textContent).toBe(`${translate('common.copy')} - RAW warning Close 12345`);
  }
  expect(state.load).toHaveBeenCalledExactlyOnceWith('Close');
});
