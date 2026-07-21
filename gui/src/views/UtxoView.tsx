// UTXO view — unspent transaction outputs (detailed table)
import { useEffect, useState } from 'react';
import { api } from '../api';
import { useStore } from '../store';

export function UtxoView() {
  const { activeAccountId } = useStore();
  const [utxos, setUtxos] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (activeAccountId === null) return;
    setLoading(true);
    api.getUtxos(activeAccountId)
      .then((r: any) => setUtxos(r.utxos || []))
      .catch(() => setUtxos([]))
      .finally(() => setLoading(false));
  }, [activeAccountId]);

  if (loading) return <div className="p-4 text-gray-400">Loading UTXOs…</div>;
  if (!utxos.length) return <div className="p-4 text-gray-400">No unspent outputs.</div>;

  const totalValue = utxos.reduce((a, u) => a + (u.value || 0), 0);

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold mb-3 text-accent">Unspent Outputs (UTXOs)</h2>
      <div className="text-sm text-gray-400 mb-3">{utxos.length} UTXOs — Total: {totalValue.toLocaleString()} sat</div>
      <div className="bg-void-900 rounded-lg border border-void-700 overflow-hidden">
        <div className="flex border-b border-void-700 px-4 py-2 text-xs text-gray-400 font-medium">
          <div className="flex-1">TX Hash</div>
          <div className="w-16 text-right">Vout</div>
          <div className="w-24 text-right">Value</div>
          <div className="w-20 text-right">Type</div>
        </div>
        {utxos.map((u, i) => (
          <div key={i} className="flex px-4 py-2 border-b border-void-800 hover:bg-void-800 transition-colors">
            <div className="flex-1 text-sm font-mono text-gray-300 truncate">{u.tx_hash?.slice(0, 32) || 'unknown'}…</div>
            <div className="w-16 text-right text-sm text-gray-300">{u.vout}</div>
            <div className="w-24 text-right text-sm text-gray-100">{u.value} sat</div>
            <div className="w-20 text-right text-xs text-gray-400">{u.is_coinbase ? 'coinbase' : 'p2pkh'}</div>
          </div>
        ))}
      </div>
    </div>
  );
}