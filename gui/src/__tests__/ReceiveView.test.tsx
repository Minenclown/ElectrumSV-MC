import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ReceiveView } from '../views/ReceiveView';

// Mock api
vi.mock('../api', () => ({
  api: {
    getReceiveAddress: vi.fn(),
    createPaymentRequest: vi.fn(),
    generateQr: vi.fn().mockResolvedValue({ svg: '<svg></svg>' }),
    parseBip276Uri: vi.fn(),
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

const SAMPLE_ADDRESS = { address: '1MoGdAdfSdf3456', key_id: 5 };

describe('ReceiveView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupStore();
    mockApi.getReceiveAddress.mockResolvedValue(SAMPLE_ADDRESS);
    mockApi.createPaymentRequest.mockResolvedValue({ uri: 'bitcoin:1MoGdAdfSdf3456?amount=1000', address: '1MoGdAdfSdf3456', amount: 1000, label: null, paymentrequest_id: 1 });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('New Address button calls getReceiveAddress', async () => {
    render(<ReceiveView />);

    await waitFor(() => {
      expect(mockApi.getReceiveAddress).toHaveBeenCalledWith(1);
    });
  });

  it('address is rendered after loading', async () => {
    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });
  });

  it('Show QR button generates QR code', async () => {
    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const showQrButton = screen.getByText('Show QR');
    fireEvent.click(showQrButton);

    // QR code area should now show SVG content (dangerouslySetInnerHTML)
    await waitFor(() => {
      const qrContainer = document.querySelector('.bg-white.p-1');
      expect(qrContainer).toBeTruthy();
    });
  });

  it('Copy button calls clipboard.writeText', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText },
    });

    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const copyButton = screen.getByText('Copy');
    fireEvent.click(copyButton);

    expect(writeText).toHaveBeenCalledWith('1MoGdAdfSdf3456');
  });

  it('BIP276 Parse button calls parseBip276Uri and shows decoded data', async () => {
    const sampleUri = 'bitcoin-script://1234567890';
    mockApi.parseBip276Uri.mockResolvedValue({
      valid: true,
      prefix: 'bitcoin-script',
      version: 1,
      network: 1,
      data_hex: '76a91400112233445566778899aabbccddeeff',
      error: null,
    });

    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const input = screen.getByPlaceholderText('bitcoin-script://...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: sampleUri } });

    const parseButton = screen.getByText('Parse');
    fireEvent.click(parseButton);

    await waitFor(() => {
      expect(mockApi.parseBip276Uri).toHaveBeenCalledWith(sampleUri);
    });

    await waitFor(() => {
      expect(screen.getByText('76a91400112233445566778899aabbccddeeff')).toBeTruthy();
      expect(screen.getByText(/Mainnet/)).toBeTruthy();
    });
  });

  it('BIP276 parse shows error in red on invalid URI', async () => {
    mockApi.parseBip276Uri.mockResolvedValue({
      valid: false,
      prefix: null,
      version: null,
      network: null,
      data_hex: null,
      error: 'bad checksum',
    });

    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const input = screen.getByPlaceholderText('bitcoin-script://...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'bitcoin-script://bad' } });

    fireEvent.click(screen.getByText('Parse'));

    await waitFor(() => {
      const err = screen.getByText('bad checksum');
      expect(err.className).toContain('red');
    });
  });

  it('BIP276 Show QR button generates QR code for the URI', async () => {
    const sampleUri = 'bitcoin-script://abc123';
    mockApi.parseBip276Uri.mockResolvedValue({
      valid: true,
      prefix: 'bitcoin-script',
      version: 1,
      network: 2,
      data_hex: 'deadbeef',
      error: null,
    });

    render(<ReceiveView />);

    await waitFor(() => {
      expect(screen.getByText('1MoGdAdfSdf3456')).toBeTruthy();
    });

    const input = screen.getByPlaceholderText('bitcoin-script://...') as HTMLInputElement;
    fireEvent.change(input, { target: { value: sampleUri } });
    fireEvent.click(screen.getByText('Parse'));

    await waitFor(() => {
      expect(screen.getByText('deadbeef')).toBeTruthy();
    });

    // Two "Show QR" buttons exist (one for address, one for BIP276).
    // The BIP276 section is after the address list, so click the last match.
    const showQrButtons = screen.getAllByText('Show QR');
    fireEvent.click(showQrButtons[showQrButtons.length - 1]);

    await waitFor(() => {
      expect(mockApi.generateQr).toHaveBeenCalledWith(sampleUri, expect.anything());
    });
  });
});