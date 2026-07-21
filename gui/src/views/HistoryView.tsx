// History view — transaction history list with TX detail panel
// Enhanced: decodes on-chain data (Ordinals, OP_RETURN, STAS tokens)
import { useEffect, useState } from 'react';
import { api, type DecodedOutput } from '../api';
import { useStore } from '../store';

interface TxDetail {
  txid: string;
  status: string;
  raw_tx?: string;
  account_id?: number;
  inputs?: { prev_tx_hash: string; prev_vout: number; script_sig: string; sequence: number }[];
  outputs?: { value: number; script_pubkey: string }[];
  fee?: number;
}

export function HistoryView() {
  const { activeAccountId, setError, historyRefreshKey } = useStore();
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTx, setSelectedTx] = useState<TxDetail | null>(null);
  const [txLoading, setTxLoading] = useState(false);
  const [txLabel, setTxLabel] = useState('');
  const [labelSaved, setLabelSaved] = useState(false);
  const [decodedOutputs, setDecodedOutputs] = useState<DecodedOutput[]>([]);
  const [decoding, setDecoding] = useState(false);

  useEffect(() => {
    if (activeAccountId === null) return;
    setLoading(true);
    api.getHistory(activeAccountId)
      .then((r: any) => setHistory(Array.isArray(r) ? r : (r.history || [])))
      .catch((e: Error) => {
        setError(`History: ${e.message}`);
        setHistory([]);
      })
      .finally(() => setLoading(false));
  }, [activeAccountId, setError, historyRefreshKey]);

  const handleTxClick = async (txHash: string) => {
    setTxLoading(true);
    setSelectedTx(null);
    setDecodedOutputs([]);
    setLabelSaved(false);
    try {
      const detail: any = await api.getTransaction(txHash);
      setSelectedTx(detail);
      setTxLabel(detail?.label || '');

      // Decode outputs for on-chain data
      if (detail?.outputs && detail.outputs.length > 0) {
        setDecoding(true);
        const outputs = detail.outputs.map((o: any) => ({
          value: o.value,
          script_pubkey: o.script_pubkey || '',
        }));
        try {
          const decoded = await api.decodeTxOutputs(outputs);
          setDecodedOutputs(decoded);
        } catch (e) {
          // Decoding is best-effort — don't fail the whole view
          console.error('Decode failed:', e);
        } finally {
          setDecoding(false);
        }
      }
    } catch (e: any) {
      setError(`TX detail: ${e.message}`);
    } finally {
      setTxLoading(false);
    }
  };

  const handleSaveTxLabel = async () => {
    if (!selectedTx) return;
    try {
      await api.setTxLabel(selectedTx.txid, txLabel);
      setLabelSaved(true);
      setTimeout(() => setLabelSaved(false), 2000);
    } catch (e: any) {
      setError(`TX label: ${e.message}`);
    }
  };

  // Render decoded output badge
  const renderDecodedBadge = (decoded: DecodedOutput | undefined) => {
    if (!decoded || decoded.kind.type === 'plain') return null;
    const k = decoded.kind;
    const badges: Record<string, { icon: string; label: string; color: string }> = {
      ordinal: { icon: '🖼', label: k.content_type || 'Ordinal', color: 'text-purple-400' },
      op_return_protocol: { icon: '📎', label: k.protocol || 'OP_RETURN', color: 'text-blue-400' },
      stas_token: { icon: '🪙', label: k.symbol || 'Token', color: 'text-yellow-400' },
    };
    const badge = badges[k.type];
    if (!badge) return null;
    return (
      <span className={`text-xs ${badge.color} ml-2`}>
        {badge.icon} {badge.label}
      </span>
    );
  };

  // Render decoded output detail
  const renderDecodedDetail = (decoded: DecodedOutput) => {
    const k = decoded.kind;
    switch (k.type) {
      case 'ordinal':
        return (
          <div className="mt-2 bg-void-700 p-2 rounded">
            <div className="text-xs text-purple-400 mb-1">
              🖼 1Sat Ordinal — {k.protocol}
            </div>
            <div className="text-xs text-gray-400">
              Type: {k.content_type}
            </div>
            {k.content_text && (
              <div className="text-xs text-gray-300 mt-1 break-all">
                {k.content_text}
              </div>
            )}
          </div>
        );
      case 'op_return_protocol':
        return (
          <div className="mt-2 bg-void-700 p-2 rounded">
            <div className="text-xs text-blue-400 mb-1">
              📎 {k.protocol} Protocol
            </div>
            <div className="text-xs text-gray-400 font-mono break-all">
              {JSON.stringify(k.data)}
            </div>
          </div>
        );
      case 'stas_token':
        return (
          <div className="mt-2 bg-void-700 p-2 rounded">
            <div className="text-xs text-yellow-400 mb-1">
              🪙 STAS Token — {k.symbol || 'Unknown'}
            </div>
            <div className="text-xs text-gray-400">
              {k.amount != null ? `${k.amount} units` : 'Amount unknown'}
            </div>
            {k.contract_txid && (
              <div className="text-xs font-mono text-gray-500 truncate mt-1">
                Contract: {k.contract_txid.slice(0, 24)}...
              </div>
            )}
          </div>
        );
      default:
        return null;
    }
  };

  if (loading) return <div className="p-4 text-gray-400">Loading history...</div>;
  if (!history.length) return <div className="p-4 text-gray-400">No transactions yet.</div>;

  return (
    <div className="flex h-full">
      {/* History table */}
      <div className={`p-4 ${selectedTx ? 'flex-1' : 'w-full'}`}>
        <h2 className="text-lg font-semibold mb-3 text-accent">Transaction History</h2>
        <div className="bg-void-900 rounded-lg border border-void-700 overflow-hidden">
          {/* Table header */}
          <div className="flex border-b border-void-700 px-4 py-2 text-xs text-gray-400 font-medium">
            <div className="flex-1">Date</div>
            <div className="flex-1">TX Hash</div>
            <div className="w-24 text-right">Amount</div>
            <div className="w-20 text-right">Status</div>
          </div>
          {/* Rows */}
          {history.map((tx, i) => {
            const isIncoming = tx.value_delta > 0;
            const status = tx.status || (tx.height > 0 ? 'confirmed' : 'pending');
            const date = tx.height > 0 ? `Block ${tx.height}` : 'Pending';
            return (
              <div
                key={i}
                onClick={() => handleTxClick(tx.tx_hash)}
                className={`flex px-4 py-2.5 border-b border-void-800 hover:bg-void-800 transition-colors cursor-pointer ${
                  selectedTx?.txid === tx.tx_hash ? 'bg-void-800 border-l-2 border-accent' : ''
                }`}
              >
                <div className="flex-1 text-sm text-gray-400">{date}</div>
                <div className="flex-1 text-sm font-mono text-gray-300 truncate">
                  {tx.tx_hash?.slice(0, 24) || 'unknown'}...
                </div>
                <div className={`w-24 text-right text-sm font-medium ${isIncoming ? 'text-success' : 'text-danger'}`}>
                  {isIncoming ? '+' : ''}{tx.value_delta || 0} sat
                </div>
                <div className="w-20 text-right">
                  <span className={`text-xs px-2 py-0.5 rounded-full ${
                    status === 'confirmed' ? 'bg-success/20 text-success' : 'bg-warning/20 text-warning'
                  }`}>
                    {status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* TX Detail Panel */}
      {selectedTx && (
        <div className="w-96 border-l border-void-700 bg-void-900 p-4 overflow-y-auto">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-semibold text-accent">Transaction Details</h3>
            <button
              onClick={() => setSelectedTx(null)}
              className="text-gray-400 hover:text-gray-100 text-sm"
            >
              Close
            </button>
          </div>

          {txLoading ? (
            <div className="text-gray-400 text-sm">Loading...</div>
          ) : selectedTx.status === 'not_found' ? (
            <div className="text-gray-400 text-sm">Transaction not found in wallet.</div>
          ) : (
            <div className="space-y-4">
              {/* TXID */}
              <div>
                <div className="text-xs text-gray-400 mb-1">Transaction ID</div>
                <div className="font-mono text-xs text-gray-300 break-all bg-void-800 p-2 rounded">
                  {selectedTx.txid}
                </div>
              </div>

              {/* TX Label */}
              <div>
                <div className="text-xs text-gray-400 mb-1">Label</div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={txLabel}
                    onChange={(e) => setTxLabel(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleSaveTxLabel(); }}
                    placeholder="— add label —"
                    className="flex-1 bg-void-800 border border-void-700 rounded px-2 py-1.5 text-xs text-gray-100 focus:border-accent outline-none"
                  />
                  <button
                    onClick={handleSaveTxLabel}
                    className="bg-accent text-white rounded px-3 py-1.5 text-xs font-medium"
                  >
                    {labelSaved ? '✓' : 'Set'}
                  </button>
                </div>
              </div>

              {/* Status */}
              <div>
                <div className="text-xs text-gray-400 mb-1">Status</div>
                <span className="text-xs px-2 py-0.5 rounded-full bg-success/20 text-success">
                  Found
                </span>
              </div>

              {/* Account */}
              {selectedTx.account_id !== undefined && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">Account</div>
                  <div className="text-sm text-gray-300">#{selectedTx.account_id}</div>
                </div>
              )}

              {/* Fee */}
              {selectedTx.fee !== undefined && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">Fee</div>
                  <div className="text-sm text-gray-300">{selectedTx.fee.toLocaleString()} sat</div>
                </div>
              )}

              {/* Inputs */}
              {selectedTx.inputs && selectedTx.inputs.length > 0 && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">Inputs ({selectedTx.inputs.length})</div>
                  {selectedTx.inputs.map((inp, i) => (
                    <div key={i} className="bg-void-800 p-2 rounded mb-1 text-xs">
                      <div className="font-mono text-gray-400 truncate">{inp.prev_tx_hash?.slice(0, 32) || 'unknown'}...</div>
                      <div className="text-gray-400">vout: {inp.prev_vout}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* Outputs with decoded data */}
              {selectedTx.outputs && selectedTx.outputs.length > 0 && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">
                    Outputs ({selectedTx.outputs.length})
                    {decoding && <span className="ml-2 text-accent">decoding...</span>}
                  </div>
                  {selectedTx.outputs.map((out, i) => {
                    const decoded = decodedOutputs[i];
                    return (
                      <div key={i} className="bg-void-800 p-2 rounded mb-1 text-xs">
                        <div className="flex items-center">
                          <div className="text-gray-300">{out.value.toLocaleString()} sat</div>
                          {renderDecodedBadge(decoded)}
                        </div>
                        <div className="font-mono text-gray-400 truncate mt-1">
                          {out.script_pubkey?.slice(0, 40) || ''}...
                        </div>
                        {decoded && renderDecodedDetail(decoded)}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Raw TX */}
              {selectedTx.raw_tx && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">Raw Transaction</div>
                  <div className="font-mono text-xs text-gray-400 bg-void-800 p-2 rounded break-all max-h-32 overflow-y-auto">
                    {selectedTx.raw_tx.length > 500
                      ? selectedTx.raw_tx.slice(0, 500) + '...'
                      : selectedTx.raw_tx}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}