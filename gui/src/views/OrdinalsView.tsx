// OrdinalsView — 1Sat Ordinals (NFT) browser
//
// Shows all detected 1Sat Ordinal inscriptions from the wallet's
// transaction history. When a transaction output is clicked, the
// Rust backend decodes the inscription envelope and returns the
// content type, content data, and protocol.

import { useEffect, useState } from 'react';
import { api, type DecodedOutput } from '../api';
import { useStore } from '../store';

export function OrdinalsView() {
  const { activeAccountId, setError } = useStore();
  const [ordinals, setOrdinals] = useState<DecodedOutput[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<DecodedOutput | null>(null);

  useEffect(() => {
    if (activeAccountId === null) return;
    setLoading(true);
    // Get UTXOs — 1-satoshi outputs are potential ordinals
    api.getUtxos(activeAccountId)
      .then(async (utxos: any[]) => {
        // Filter for 1-satoshi outputs (ordinal candidates)
        const oneSatOutputs = utxos
          .filter((u: any) => u.value === 1)
          .map((u: any) => ({
            value: u.value,
            script_pubkey: u.script_pubkey || '',
          }));

        if (oneSatOutputs.length === 0) {
          setOrdinals([]);
          return;
        }

        // Decode each output to check for ordinal inscriptions
        const results = await api.getOrdinals(oneSatOutputs);
        setOrdinals(results);
      })
      .catch((e: Error) => {
        setError(`Ordinals: ${e.message}`);
        setOrdinals([]);
      })
      .finally(() => setLoading(false));
  }, [activeAccountId, setError]);

  const renderContent = (ord: DecodedOutput) => {
    const k = ord.kind;
    if (k.content_text) {
      return (
        <div className="bg-void-800 p-3 rounded text-sm text-gray-300 max-h-48 overflow-auto">
          {k.content_text}
        </div>
      );
    }
    if (k.content_type?.startsWith('image/')) {
      // For image content, we'd need a data URI or a link to the content
      // For now, show the hex with a note
      return (
        <div className="bg-void-800 p-3 rounded">
          <div className="text-xs text-gray-400 mb-2">
            Image content ({k.content_type}) — {k.content_hex?.length ?? 0} hex chars
          </div>
          <div className="font-mono text-xs text-gray-500 break-all max-h-32 overflow-auto">
            {(k.content_hex?.length ?? 0) > 200 ? k.content_hex!.slice(0, 200) + '...' : k.content_hex ?? ''}
          </div>
        </div>
      );
    }
    return (
      <div className="bg-void-800 p-3 rounded font-mono text-xs text-gray-500 break-all max-h-32 overflow-auto">
        {(k.content_hex?.length ?? 0) > 200 ? k.content_hex!.slice(0, 200) + '...' : k.content_hex ?? ''}
      </div>
    );
  };

  if (loading) return <div className="p-4 text-gray-400">Loading ordinals...</div>;

  return (
    <div className="flex h-full">
      <div className={`p-4 ${selected ? 'flex-1' : 'w-full'}`}>
        <h2 className="text-lg font-semibold mb-3 text-accent">1Sat Ordinals</h2>
        {!ordinals.length ? (
          <div className="text-gray-400 text-sm">
            No ordinal inscriptions found. 1-satoshi outputs with NFT inscriptions will appear here.
          </div>
        ) : (
          <div className="space-y-2">
            {ordinals.map((ord, i) => (
              <div
                key={i}
                onClick={() => setSelected(ord)}
                className={`bg-void-900 rounded-lg p-3 border cursor-pointer transition-colors hover:bg-void-800 ${
                  selected?.output_index === ord.output_index ? 'border-accent' : 'border-void-700'
                }`}
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">
                    {ord.kind.content_type?.startsWith('image/') ? '🖼' : '📄'}
                  </span>
                  <div className="flex-1">
                    <div className="text-sm text-gray-200">
                      {ord.kind.protocol} — {ord.kind.content_type}
                    </div>
                    <div className="text-xs text-gray-500">
                      Output #{ord.output_index} — 1 sat
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {selected && (
        <div className="w-96 border-l border-void-700 bg-void-900 p-4 overflow-y-auto">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-semibold text-accent">Inscription Details</h3>
            <button
              onClick={() => setSelected(null)}
              className="text-gray-400 hover:text-gray-100 text-sm"
            >
              Close
            </button>
          </div>
          <div className="space-y-3">
            <div>
              <div className="text-xs text-gray-400 mb-1">Protocol</div>
              <div className="text-sm text-gray-200">{selected.kind.protocol}</div>
            </div>
            <div>
              <div className="text-xs text-gray-400 mb-1">Content Type</div>
              <div className="text-sm text-gray-200">{selected.kind.content_type}</div>
            </div>
            <div>
              <div className="text-xs text-gray-400 mb-1">Content</div>
              {renderContent(selected)}
            </div>
            <div>
              <div className="text-xs text-gray-400 mb-1">Script</div>
              <div className="font-mono text-xs text-gray-500 bg-void-800 p-2 rounded break-all max-h-24 overflow-auto">
                {selected.script_pubkey_hex.length > 120 ? selected.script_pubkey_hex.slice(0, 120) + '...' : selected.script_pubkey_hex}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}