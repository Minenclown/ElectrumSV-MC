// Console view — Rust backend log viewer (Tauri mode, no Python daemon)
// Shows a placeholder since the Python daemon has been removed.
// Future: could show Rust backend logs via Tauri.
import { useState } from 'react';
import { useTranslation } from '../i18n';

export function ConsoleView() {
  const { t } = useTranslation();
  const _ = t; // suppress unused warning
  const [logContent] = useState<string>(
    'Python daemon removed — running in Tauri native mode.\n' +
    'Backend logs are handled by the Rust runtime (env_logger).\n' +
    'Check terminal output for Rust backend logs.'
  );

  return (
    <div className="p-4 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-accent">Backend Log</h2>
      </div>
      <div className="flex-1 bg-void-950 rounded-lg p-3 overflow-auto font-mono text-xs text-gray-400 border border-void-700">
        <pre className="whitespace-pre-wrap break-words">{logContent}</pre>
      </div>
      <div className="text-xs text-gray-400 mt-2">
        Tauri native mode — no daemon log available
      </div>
    </div>
  );
}