// Status bar — bottom of window (ElectrumSV-style)
import { useStore } from '../store';
import { useTranslation } from '../i18n';
import { useEffect, useRef } from 'react';

export function StatusBar() {
  const { connected, network, blockHeight, server, error, setError } = useStore();
  const { t } = useTranslation();
  const errorTimer = useRef<number | null>(null);

  useEffect(() => {
    if (error) {
      if (errorTimer.current) clearTimeout(errorTimer.current);
      errorTimer.current = window.setTimeout(() => setError(null), 10000);
    }
    return () => {
      if (errorTimer.current) clearTimeout(errorTimer.current);
    };
  }, [error, setError]);

  return (
    <div className="flex items-center justify-between bg-void-900 border-t border-void-700 px-4 py-1.5 text-xs text-gray-400">
      <div className="flex items-center gap-3">
        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-success' : 'bg-danger'}`} />
        <span>{connected ? t.status.connected : t.status.disconnected}</span>
        <span className="text-gray-400">|</span>
        <span>{network}</span>
        {server && (
          <>
            <span className="text-gray-400">|</span>
            <span className="font-mono">{server}</span>
          </>
        )}
      </div>
      <div className="flex items-center gap-3">
        {error && (
          <span className="text-danger truncate max-w-md" title={error}>
            {error}
          </span>
        )}
        <span>{t.status.block}: {blockHeight.toLocaleString()}</span>
      </div>
    </div>
  );
}