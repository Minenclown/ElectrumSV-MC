import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { HistoryView } from '../views/HistoryView';

// Mock api
vi.mock('../api', () => ({
  api: {
    getHistory: vi.fn(),
    getTransaction: vi.fn(),
    decodeTxOutputs: vi.fn().mockResolvedValue([]),
  },
}));

// Mock store
vi.mock('../store', () => ({
  useStore: vi.fn(),
}));

import { api } from '../api';
import { useStore } from '../store';

const mockApi = vi.mocked(api);
const mockUseStore = vi.mocked(useStore);

function setupStore(overrides: Record<string, any> = {}) {
  mockUseStore.mockReturnValue({
    activeAccountId: 1,
    setError: vi.fn(),
    ...overrides,
  });
}

const SAMPLE_HISTORY = [
  { tx_hash: 'abc123def456', height: 700000, value_delta: 5000, status: 'confirmed' },
  { tx_hash: 'xyz789ghi012', height: 0, value_delta: -2000, status: 'pending' },
];

const SAMPLE_TX_DETAIL = {
  txid: 'abc123def456',
  status: 'found',
  account_id: 1,
  fee: 500,
  inputs: [{ prev_tx_hash: 'prevhash123', prev_vout: 0, script_sig: 'sig', sequence: 0 }],
  outputs: [{ value: 4500, script_pubkey: 'pubkey123' }],
  raw_tx: '01000000...',
  label: null,
};

// Helper: find the TX row by partial hash text
function findTxRow(hash: string) {
  return screen.getByText(new RegExp(hash)).closest('[class*="cursor-pointer"]');
}

describe('HistoryView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupStore();
    mockApi.getHistory.mockResolvedValue(SAMPLE_HISTORY);
    mockApi.getTransaction.mockResolvedValue(SAMPLE_TX_DETAIL);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders transactions after loading', async () => {
    render(<HistoryView />);

    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeTruthy();
    });
  });

  it('clicking a TX opens detail panel with txid', async () => {
    render(<HistoryView />);

    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeTruthy();
    });

    const row = findTxRow('abc123def456');
    fireEvent.click(row!);

    await waitFor(() => {
      expect(mockApi.getTransaction).toHaveBeenCalledWith('abc123def456');
    });

    await waitFor(() => {
      expect(screen.getByText('Transaction Details')).toBeTruthy();
    });
  });

  it('detail panel shows inputs and outputs', async () => {
    render(<HistoryView />);

    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeTruthy();
    });

    const row = findTxRow('abc123def456');
    fireEvent.click(row!);

    await waitFor(() => {
      expect(screen.getByText(/Inputs \(1\)/)).toBeTruthy();
      expect(screen.getByText(/Outputs \(1\)/)).toBeTruthy();
    });
  });

  it('close button closes detail panel', async () => {
    render(<HistoryView />);

    await waitFor(() => {
      expect(screen.getByText(/abc123def456/)).toBeTruthy();
    });

    const row = findTxRow('abc123def456');
    fireEvent.click(row!);

    await waitFor(() => {
      expect(screen.getByText('Transaction Details')).toBeTruthy();
    });

    fireEvent.click(screen.getByText('Close'));

    await waitFor(() => {
      expect(screen.queryByText('Transaction Details')).toBeNull();
    });
  });
});