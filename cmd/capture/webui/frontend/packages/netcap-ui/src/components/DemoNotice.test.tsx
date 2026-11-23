import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import DemoNotice, { DEMO_NOTICE_STORAGE_KEY } from './DemoNotice';

const { getStatus } = vi.hoisted(() => ({ getStatus: vi.fn() }));
vi.mock('../lib/api', () => ({ api: { getStatus } }));

function renderNotice() {
  return render(<SWRConfig value={{ provider: () => new Map() }}><DemoNotice /></SWRConfig>);
}

beforeEach(() => { getStatus.mockReset(); window.localStorage.clear(); });
afterEach(cleanup);

describe('demo notice', () => {
  it('shows once in service mode and remembers dismissal', async () => {
    getStatus.mockResolvedValue({ isServiceMode: true });
    renderNotice();
    expect(await screen.findByText('Welcome to the Netcap demo')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /GitHub Repository/ })).toHaveAttribute('href', 'https://github.com/dreadl0ck/netcap');
    expect(screen.getByRole('link', { name: /Documentation/ })).toHaveAttribute('href', 'https://docs.netcap.io');
    fireEvent.click(screen.getByRole('button', { name: 'Start exploring' }));
    expect(window.localStorage.getItem(DEMO_NOTICE_STORAGE_KEY)).toBe('1');
    await waitFor(() => expect(screen.queryByText('Welcome to the Netcap demo')).not.toBeInTheDocument());

    cleanup();
    renderNotice();
    await waitFor(() => expect(getStatus).toHaveBeenCalledTimes(2));
    expect(screen.queryByText('Welcome to the Netcap demo')).not.toBeInTheDocument();
  });

  it('stays hidden outside service mode', async () => {
    getStatus.mockResolvedValue({ isServiceMode: false });
    renderNotice();
    await waitFor(() => expect(getStatus).toHaveBeenCalled());
    expect(screen.queryByText('Welcome to the Netcap demo')).not.toBeInTheDocument();
  });
});
