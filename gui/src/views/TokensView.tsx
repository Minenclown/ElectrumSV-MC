// TokensView — STAS token transfers and OP_RETURN protocol data
//
// Shows two panels:
// 1. STAS Token transfers detected in transaction outputs
// 2. OP_RETURN protocol data (B, MAP, Bcat, BAP, 21E8)

import { useEffect, useState } from 'react';
import { api, type DecodedOutput } from '../api';
import { useStore } from '../store';

type Tab = 'tokens' | 'protocols';

export function TokensView() {
  const { activeAccountId, setError } = useStore();
  const [tab, setTab] = useState<Tab>('tokens');
  const [tokens, setTokens] = useState<DecodedOutput[]>([]);
  const [protocols, setProtocols] = useState<DecodedOutput[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (activeAccountId === null) return;
    setLoading(true);
    api.getUtxos(activeAccountId)
      .then(async (utxos: any[]) => {
        const outputs = utxos.map((u: any) => ({
          value: u.value,
          script_pubkey: u.script_pubkey || '',
        }));

        const [tokenResults, protocolResults] = await Promise.all([
          api.getTokenTransfers(outputs),
          api.getProtocolData(outputs),
        ]);
        setTokens(tokenResults);
        setProtocols(protocolResults);
      })
      .catch((e: Error) => {
        setError(`Tokens: ${e.message}`);
      })
      .finally(() => setLoading(false));
  }, [activeAccountId, setError]);

  if (loading) return <div className="p-4 text-gray-400">Loading tokens...</div>;

  return (
    <div className="p-4 h-full flex flex-col">
      <h2 className="text-lg font-semibold mb-3 text-accent">Tokens &amp; Protocols</h2>

      {/* Tab bar */}
      <div className="flex gap-2 mb-4">
        <button
          onClick={() => setTab('tokens')}
          className={`px-3 py-1.5 rounded text-sm ${
            tab === 'tokens'
              ? 'bg-accent text-white'
              : 'bg-void-800 text-gray-400 hover:text-gray-200'
          }`}
        >
          STAS Tokens ({tokens.length})
        </button>
        <button
          onClick={() => setTab('protocols')}
          className={`px-3 py-1.5 rounded text-sm ${
            tab === 'protocols'
              ? 'bg-accent text-white'
              : 'bg-void-800 text-gray-400 hover:text-gray-200'
          }`}
        >
          OP_RETURN Protocols ({protocols.length})
        </button>
      </div>

      {/* Content */}
      {tab === 'tokens' ? (
        <div className="flex-1 overflow-auto">
          {!tokens.length ? (
            <div className="text-gray-400 text-sm">
              No STAS token transfers found. Token outputs will appear here when detected.
            </div>
          ) : (
            <div className="space-y-2">
              {tokens.map((t, i) => (
                <div key={i} className="bg-void-900 rounded-lg p-3 border border-void-700">
                  <div className="flex items-center gap-3">
                    <span className="text-xl">🪙</span>
                    <div className="flex-1">
                      <div className="text-sm text-gray-200">
                        {t.kind.symbol || 'Unknown Token'}
                      </div>
                      <div className="text-xs text-gray-500">
                        {t.kind.amount != null ? `${t.kind.amount} units` : 'Amount unknown'}
                      </div>
                      {t.kind.contract_txid && (
                        <div className="text-xs font-mono text-gray-500 truncate mt-1">
                          Contract: {t.kind.contract_txid.slice(0, 24)}...
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          {!protocols.length ? (
            <div className="text-gray-400 text-sm">
              No recognized OP_RETURN protocols found. B, MAP, Bcat, BAP, and 21E8 protocol data will appear here.
            </div>
          ) : (
            <div className="space-y-2">
              {protocols.map((p, i) => (
                <div key={i} className="bg-void-900 rounded-lg p-3 border border-void-700">
                  <div className="flex items-center gap-3 mb-2">
                    <span className="text-xl">
                      {p.kind.protocol === 'B' ? '📎' :
                       p.kind.protocol === 'MAP' ? '🗺' :
                       p.kind.protocol === 'Bcat' ? '🗂' :
                       p.kind.protocol === 'BAP' ? '🔐' :
                       p.kind.protocol === '21E8' ? '⚡' : '📦'}
                    </span>
                    <div className="flex-1">
                      <div className="text-sm text-gray-200">
                        {p.kind.protocol} Protocol
                      </div>
                      <div className="text-xs text-gray-500">
                        Output #{p.output_index} — {p.value} sat
                      </div>
                    </div>
                  </div>
                  <div className="bg-void-800 p-2 rounded text-xs text-gray-400 font-mono break-all">
                    {JSON.stringify(p.kind.data, null, 2)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}