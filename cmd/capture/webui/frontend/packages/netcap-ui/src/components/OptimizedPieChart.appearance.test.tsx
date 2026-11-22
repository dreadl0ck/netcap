import { render } from '@testing-library/react';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { beforeEach, expect, it, vi } from 'vitest';
import OptimizedPieChart from './OptimizedPieChart';
import { appearanceTokens } from '../lib/appearance';

const chart = vi.hoisted(() => ({ setOption: vi.fn(), on: vi.fn(), off: vi.fn(), dispose: vi.fn(), resize: vi.fn() }));
const init = vi.hoisted(() => vi.fn());
vi.mock('echarts/core', () => ({ use: vi.fn(), init }));

beforeEach(() => {
  vi.clearAllMocks();
  init.mockReturnValue(chart);
  vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} });
});

it('repaints chart, legend, labels and tooltip without reinitializing or resubmitting data/legend selection', () => {
  const option = { legend: { selected: { DNS: false } }, series: [{ type: 'pie', data: [{ name: 'DNS', value: 3 }] }] };
  const view = (mode: 'dark' | 'light') => <ThemeProvider theme={createTheme({ palette: { mode } })}><OptimizedPieChart option={option} /></ThemeProvider>;
  const { rerender, unmount } = render(view('dark'));
  chart.setOption.mockClear();
  rerender(view('light'));
  const c = appearanceTokens('light');
  expect(init).toHaveBeenCalledTimes(1);
  expect(chart.dispose).not.toHaveBeenCalled();
  expect(chart.setOption).toHaveBeenCalledTimes(1);
  expect(chart.setOption).toHaveBeenCalledWith(expect.objectContaining({
    backgroundColor: c.canvas, legend: expect.objectContaining({ textStyle: { color: c.muted } }),
    tooltip: expect.objectContaining({ backgroundColor: c.surface, textStyle: { color: c.text } }),
  }));
  expect(chart.setOption.mock.calls[0][0].legend.selected).toBeUndefined();
  expect(chart.setOption.mock.calls[0][0].series[0].data).toBeUndefined();
  unmount();
  expect(chart.dispose).toHaveBeenCalledTimes(1);
});
