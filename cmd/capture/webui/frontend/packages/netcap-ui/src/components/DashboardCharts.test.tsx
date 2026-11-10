import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import DashboardChartTile from './DashboardChartTile';
import { layoutsFor } from './CustomDashboardView';
import type { DashboardChart } from '../lib/api';

const chart = (id: string, x: number, y: number): DashboardChart => ({
  id, title: id, auditType: 'File', field: 'MagikaLabel', chartType: 'pie', showLegend: true, maxDataPoints: 1000,
  layout: { x, y, w: 6, h: 4 },
} as DashboardChart);

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('dashboard layouts', () => {
  it('never overflows narrower grids and stacks small screens in reading order', () => {
    const layouts = layoutsFor([chart('b', 6, 0), chart('a', 0, 0), chart('c', 0, 4)], 12);
    for (const l of layouts.md) expect(l.x + l.w).toBeLessThanOrEqual(10);
    expect(layouts.md.map((l) => [l.x, l.w])).toEqual([[5, 5], [0, 5], [0, 5]]);
    for (const l of layouts.sm) expect(l.x + l.w).toBeLessThanOrEqual(6);
    expect(layouts.xs.map((l) => [l.i, l.x, l.w, l.y])).toEqual([['a', 0, 4, 0], ['b', 0, 4, 4], ['c', 0, 4, 8]]);
  });

  it('packs visible charts so a hidden chart leaves no hole', () => {
    const layouts = layoutsFor([chart('a', 0, 0), chart('b', 6, 0), chart('d', 6, 4)], 12, true);
    expect(layouts.lg.map((l) => [l.i, l.x, l.y])).toEqual([['a', 0, 0], ['b', 6, 0], ['d', 0, 4]]);
  });
});

describe('DashboardChartTile', () => {
  it('reports a 204 response as empty instead of an error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 204 })));
    const onEmptyChange = vi.fn();
    render(<DashboardChartTile chart={chart('a', 0, 0)} editing available onEmptyChange={onEmptyChange} />);
    await waitFor(() => expect(onEmptyChange).toHaveBeenCalledWith('a', true));
    expect(screen.queryByText('Failed to render chart')).not.toBeInTheDocument();
  });

  it('keeps real failures visible', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('corrupt audit file', { status: 500 })));
    const onEmptyChange = vi.fn();
    render(<DashboardChartTile chart={chart('a', 0, 0)} editing={false} available onEmptyChange={onEmptyChange} />);
    expect(await screen.findByText('Failed to render chart')).toBeInTheDocument();
    expect(screen.getByText('corrupt audit file')).toBeInTheDocument();
    expect(onEmptyChange).toHaveBeenCalledWith('a', false);
  });
});
