import { useState } from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { afterEach, expect, it, vi } from 'vitest';
import { Layout } from './Layout';
import { ReactRouterNetcapProvider } from '../adapters/react-router';
import { initializeI18n, setLocale, supportedLocales, translate } from '../lib/i18n';

vi.mock('swr', () => ({ default: () => ({ data: undefined, mutate: vi.fn() }), mutate: vi.fn() }));
afterEach(cleanup);

it('forwards the global header slot, renders full live titles/hints/captions, and preserves focus and route controls', () => {
  initializeI18n({ locale: 'en' });
  function Editor() {
    const [value, setValue] = useState('unsaved capture notes');
    return <input aria-label="Analyst notes" value={value} onChange={event => setValue(event.target.value)} />;
  }
  const { container } = render(<MemoryRouter initialEntries={['/records']}>
    <ThemeProvider theme={createTheme()}><ReactRouterNetcapProvider backendUrl="" headerActions={<button>Host controls</button>}
      navigationItems={[{ path: '/timeline', label: 'Timeline', icon: null, description: 'Timeline: Explore analyzed audit records in order of occurrence.' }]}>
      <Layout title="Investigation evidence"><Editor /></Layout>
    </ReactRouterNetcapProvider></ThemeProvider>
  </MemoryRouter>);
  expect(screen.getByRole('banner')).toContainElement(screen.getByRole('button', { name: 'Host controls' }));
  const editor = screen.getByRole('textbox');
  fireEvent.change(editor, { target: { value: 'still unsaved after presentation changes' } }); editor.focus();
  const heading = screen.getByRole('heading', { level: 1 });
  expect(heading).not.toHaveClass('MuiTypography-noWrap');
  const paths = Array.from(container.querySelectorAll('a')).map(link => link.getAttribute('href'));
  for (const locale of supportedLocales) {
    act(() => setLocale(locale));
    expect(heading).toHaveTextContent(translate('Investigation evidence'));
    expect(screen.getByText(translate('Network traffic intelligence'))).toBeInTheDocument();
    const hint = translate('Records: Explore detailed network traffic records organized by protocol type with advanced filtering.');
    expect(container.querySelector('[data-learn]')?.getAttribute('data-learn')).toBe(translate('Dashboard: Overview of system status, processing statistics, and quick access to key metrics.'));
    expect(Array.from(container.querySelectorAll('[data-learn]')).some(node => node.getAttribute('data-learn') === hint)).toBe(true);
    expect(Array.from(container.querySelectorAll('a')).map(link => link.getAttribute('href'))).toEqual(paths);
    expect(editor).toHaveValue('still unsaved after presentation changes'); expect(editor).toHaveFocus();
    expect(screen.getByRole('button', { name: 'Host controls' })).toBeInTheDocument();
  }
});
