// Receive view — address list with QR codes, Payment Requests (Phase 5)
// QR code generated via PicQr Rust backend (replaces qrcode npm package).
// BIP276 bitcoin-script:// URI parser added (Phase 6).
import { useEffect, useState, useCallback } from 'react';
import { api } from '../api';
import { useStore } from '../store';

interface AddressInfo {
  address: string;
  key_id: number | null;
  label?: string;
}

// BIP276 parse result matching Rust `Bip276Result`.
interface Bip276Result {
  valid: boolean;
  prefix: string | null;
  version: number | null;
  network: number | null;
  data_hex: string | null;
  error: string | null;
}

// Map a BIP276 network byte to a human-readable name.
// 1 = Mainnet, 2 = Testnet, 3 = STN (scaling testnet), 4 = Regtest. Byte 0 is invalid.
function networkName(byte: number | null): string {
  switch (byte) {
    case 1: return 'Mainnet';
    case 2: return 'Testnet';
    case 3: return 'STN';
    case 4: return 'Regtest';
    default: return byte !== null ? `Unknown (${byte})` : 'Unknown';
  }
}

export function ReceiveView() {
  const { activeAccountId, setError } = useStore();
  const [addresses, setAddresses] = useState<AddressInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [showQR, setShowQR] = useState<string | null>(null);
  const [qrSvg, setQrSvg] = useState<string | null>(null);
  const [paymentAmount, setPaymentAmount] = useState('');
  const [paymentLabel, setPaymentLabel] = useState('');
  const [paymentUri, setPaymentUri] = useState<string | null>(null);
  const [editingLabel, setEditingLabel] = useState<number | null>(null);
  const [labelInput, setLabelInput] = useState('');

  // BIP276 URI parser state
  const [bip276Input, setBip276Input] = useState('');
  const [bip276Result, setBip276Result] = useState<Bip276Result | null>(null);
  const [bip276Busy, setBip276Busy] = useState(false);
  const [bip276ShowQR, setBip276ShowQR] = useState(false);

  const generateQR = useCallback(async (text: string) => {
    try {
      const result = await api.generateQr(text, {
        scale: 10,
        quietZone: 4,
      });
      setQrSvg(result.svg);
    } catch {
      setQrSvg(null);
      setError('QR code generation failed');
    }
  }, [setError]);

  const loadAddress = async () => {
    if (activeAccountId === null) return;
    setLoading(true);
    try {
      const r = await api.getReceiveAddress(activeAccountId);
      const newAddr = { address: r.address || '', key_id: r.key_id ?? null };
      if (newAddr.address && newAddr.address !== 'not_available') {
        setAddresses((prev) => {
          if (prev.some((a) => a.address === newAddr.address)) return prev;
          return [...prev, newAddr];
        });
      }
    } catch (e: any) {
      setError(`Receive address: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setAddresses([]);
    setPaymentUri(null);
    loadAddress();
  }, [activeAccountId]);

  const handleNewAddress = async () => {
    await loadAddress();
  };

  const handleShowQR = async (addr: string) => {
    setShowQR(addr);
    setPaymentUri(null);
    await generateQR(addr);
  };

  const handleCopy = (addr: string) => {
    navigator.clipboard.writeText(addr).catch(() => {
      setError('Clipboard write failed');
    });
  };

  const handlePaymentRequest = async () => {
    if (activeAccountId === null || !addresses.length) return;
    const amount = parseInt(paymentAmount) || 0;
    try {
      const r = await api.createPaymentRequest(activeAccountId, amount, paymentLabel || undefined);
      setPaymentUri(r.uri);
      setShowQR(null);
      await generateQR(r.uri);
    } catch (e: any) {
      setError(`Payment request: ${e.message}`);
    }
  };

  const handleSaveLabel = async (keyId: number, idx: number) => {
    try {
      await api.setKeyLabel(keyId, labelInput, activeAccountId!);
      setAddresses((prev) => prev.map((a, i) => i === idx ? { ...a, label: labelInput } : a));
    } catch (e: any) {
      setError(`Label: ${e.message}`);
    }
    setEditingLabel(null);
  };

  // Parse a bitcoin-script:// BIP276 URI via the Rust backend.
  const handleParseBip276 = async () => {
    const uri = bip276Input.trim();
    if (!uri) return;
    setBip276Busy(true);
    setBip276ShowQR(false);
    setQrSvg(null);
    try {
      const r = await api.parseBip276Uri(uri) as Bip276Result;
      setBip276Result(r);
    } catch (e: any) {
      setBip276Result({
        valid: false, prefix: null, version: null, network: null,
        data_hex: null, error: e?.message ?? 'parse failed',
      });
    } finally {
      setBip276Busy(false);
    }
  };

  // Show a QR code for the parsed BIP276 URI using the existing generateQR callback.
  const handleBip276ShowQR = async () => {
    if (!bip276Input.trim()) return;
    setBip276ShowQR(true);
    await generateQR(bip276Input.trim());
  };

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold mb-4 text-accent">Receive BSV</h2>

      <div className="mb-4 flex gap-2">
        <button
          onClick={handleNewAddress}
          disabled={loading}
          className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
        >
          {loading ? 'Loading…' : 'New Address'}
        </button>
      </div>

      {/* Payment Request */}
      <div className="bg-void-900 rounded-lg p-4 border border-void-700 mb-4">
        <div className="text-sm text-gray-400 mb-2">Payment Request (BIP21)</div>
        <div className="flex gap-2 mb-2">
          <input
            type="number"
            value={paymentAmount}
            onChange={(e) => setPaymentAmount(e.target.value)}
            placeholder="Amount (satoshis)"
            className="w-32 bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
          />
          <input
            type="text"
            value={paymentLabel}
            onChange={(e) => setPaymentLabel(e.target.value)}
            placeholder="Label (optional)"
            className="flex-1 bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
          />
          <button
            onClick={handlePaymentRequest}
            className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors"
          >
            Request
          </button>
        </div>
        {paymentUri && (
          <div className="text-xs font-mono text-gray-400 break-all bg-void-800 p-2 rounded">
            {paymentUri}
          </div>
        )}
      </div>

      {addresses.length === 0 && !loading ? (
        <div className="text-gray-400">No addresses available.</div>
      ) : (
        <div className="space-y-3">
          {addresses.map((addrInfo, i) => (
            <div key={i} className="bg-void-900 rounded-lg p-4 border border-void-700 flex items-start gap-4">
              <div className="flex-shrink-0">
                {showQR === addrInfo.address || (paymentUri && showQR === null) ? (
                  qrSvg && (
                    <div
                      className="w-32 h-32 rounded-lg bg-white p-1"
                      dangerouslySetInnerHTML={{ __html: qrSvg }}
                    />
                  )
                ) : (
                  <button
                    onClick={() => handleShowQR(addrInfo.address)}
                    className="w-32 h-32 rounded-lg bg-void-800 flex items-center justify-center text-gray-400 hover:bg-void-700 transition-colors"
                  >
                    <span className="text-xs">Show QR</span>
                  </button>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs text-gray-400">Index #{i}</span>
                  {addrInfo.key_id !== null && (
                    <span className="text-xs text-gray-400">Key #{addrInfo.key_id}</span>
                  )}
                </div>
                <div className="font-mono text-sm text-gray-100 break-all bg-void-800 p-2 rounded mb-2">
                  {addrInfo.address || 'No address available'}
                </div>
                {/* Label */}
                <div className="mb-2">
                  {editingLabel === i ? (
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={labelInput}
                        onChange={(e) => setLabelInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' && addrInfo.key_id !== null) handleSaveLabel(addrInfo.key_id, i);
                          if (e.key === 'Escape') setEditingLabel(null);
                        }}
                        placeholder="Label for this address"
                        className="flex-1 bg-void-800 border border-void-700 rounded px-2 py-1 text-xs text-gray-100 focus:border-accent outline-none"
                        autoFocus
                      />
                      <button
                        onClick={() => addrInfo.key_id !== null && handleSaveLabel(addrInfo.key_id, i)}
                        className="bg-accent text-white rounded px-2 py-1 text-xs"
                      >Save</button>
                    </div>
                  ) : (
                    <button
                      onClick={() => { setEditingLabel(i); setLabelInput(addrInfo.label || ''); }}
                      className="text-xs text-gray-400 hover:text-accent transition-colors"
                    >
                      {addrInfo.label || '— add label —'}
                    </button>
                  )}
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleCopy(addrInfo.address)}
                    className="bg-void-700 hover:bg-void-600 text-gray-100 rounded-lg px-3 py-1.5 text-xs transition-colors"
                  >
                    Copy
                  </button>
                  {showQR === addrInfo.address && (
                    <button
                      onClick={() => { setShowQR(null); setQrSvg(null); setPaymentUri(null); }}
                      className="bg-void-700 hover:bg-void-600 text-gray-100 rounded-lg px-3 py-1.5 text-xs transition-colors"
                    >
                      Hide QR
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      {/* BIP276 bitcoin-script:// URI parser */}
      <div className="bg-void-900 rounded-lg p-4 border border-void-700 mt-6">
        <div className="text-sm text-gray-400 mb-2">BIP276 Script URI</div>
        <div className="flex gap-2 mb-3">
          <input
            type="text"
            value={bip276Input}
            onChange={(e) => setBip276Input(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleParseBip276(); }}
            placeholder="bitcoin-script://..."
            className="flex-1 bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm font-mono text-gray-100 focus:border-accent outline-none"
          />
          <button
            onClick={handleParseBip276}
            disabled={bip276Busy || !bip276Input.trim()}
            className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {bip276Busy ? 'Parsing…' : 'Parse'}
          </button>
        </div>

        {bip276Result && (
          <div className="mt-2">
            {bip276Result.valid ? (
              <div className="space-y-1">
                <div className="text-xs text-gray-400">
                  Prefix: <span className="text-gray-200">{bip276Result.prefix ?? '—'}</span>
                </div>
                <div className="text-xs text-gray-400">
                  Version: <span className="text-gray-200">{bip276Result.version ?? '—'}</span>
                </div>
                <div className="text-xs text-gray-400">
                  Network: <span className="text-gray-200">{networkName(bip276Result.network)}</span>
                </div>
                <div className="text-xs text-gray-400">
                  Data (hex): <span className="text-gray-200 font-mono break-all">{bip276Result.data_hex ?? '—'}</span>
                </div>
                <div className="flex gap-2 mt-2">
                  <button
                    onClick={handleBip276ShowQR}
                    className="bg-void-700 hover:bg-void-600 text-gray-100 rounded-lg px-3 py-1.5 text-xs transition-colors"
                  >
                    Show QR
                  </button>
                  {bip276ShowQR && (
                    <button
                      onClick={() => { setBip276ShowQR(false); setQrSvg(null); }}
                      className="bg-void-700 hover:bg-void-600 text-gray-100 rounded-lg px-3 py-1.5 text-xs transition-colors"
                    >
                      Hide QR
                    </button>
                  )}
                </div>
                {bip276ShowQR && qrSvg && (
                  <div
                    className="w-32 h-32 rounded-lg bg-white p-1 mt-2"
                    dangerouslySetInnerHTML={{ __html: qrSvg }}
                  />
                )}
              </div>
            ) : (
              <div className="text-xs text-red-400 break-all">
                {bip276Result.error ?? 'invalid URI'}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}