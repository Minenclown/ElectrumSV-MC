import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { StatusBar } from '../components/StatusBar';

// Mock store
vi.mock('../store', () => ({
  useStore: vi.fn(),
}));

import { useStore } from '../store';

const mockUseStore = vi.mocked(useStore);

function setupStore(overrides: Record<string, any> = {}) {
  mockUseStore.mockReturnValue({
    connected: true,
    network: 'mainnet',
    blockHeight: 700000,
    server: 'localhost:9999',
    error: null,
    setError: vi.fn(),
    ...overrides,
  });
}

describe('StatusBar', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('error is displayed in red when set', () => {
    setupStore({ error: 'Connection lost' });
    render(<StatusBar />);

    const errorEl = screen.getByText('Connection lost');
    expect(errorEl.className).toContain('text-danger');
  });

  it('error auto-clears after 10 seconds', () => {
    const setError = vi.fn();
    setupStore({ error: 'Something broke', setError });
    render(<StatusBar />);

    expect(setError).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(10000);
    });

    expect(setError).toHaveBeenCalledWith(null);
  });
});