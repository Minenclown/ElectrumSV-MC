import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
import { useStore } from '../store';
import { LandingPage } from '../views/LandingPage';

const mockInvoke = vi.mocked(invoke);

const TEST_WALLET_PATH = '/var/home/RaSt/OpenCode/electrumsv-mc/data/Test.sqlite';

describe('LandingPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useStore.setState({
      view: 'landing',
      selectedWallet: null,
      walletList: [],
    });
    mockInvoke.mockResolvedValue([
      {
        name: 'Test',
        path: TEST_WALLET_PATH,
        size_bytes: 86016,
        modified_unix: 0,
      },
    ]);
  });

  it('selects the full wallet path when opening an existing wallet', async () => {
    render(<LandingPage />);

    await waitFor(() => expect(screen.getByText('Test')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Open' }));

    expect(useStore.getState().selectedWallet).toBe(TEST_WALLET_PATH);
    expect(useStore.getState().view).toBe('login');
  });
});
