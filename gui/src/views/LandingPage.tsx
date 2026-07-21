// Landing page — wallet selector (Tauri mode, no REST API needed)
// Language selector at bottom — persisted in localStorage
import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useStore } from '../store';
import type { WalletEntry } from '../store';
import { useTranslation, type Language } from '../i18n';

export function LandingPage() {
  const { setView, setSelectedWallet, setWalletList, walletList } = useStore();
  const { t, language, setLanguage } = useTranslation();

  useEffect(() => {
    // In Tauri mode, the backend is always available (it's the same process)
    // List wallets via Tauri IPC
    invoke<any[]>('list_wallets')
      .then((wallets) => {
        const mapped: WalletEntry[] = (wallets || []).map((w) => ({
          name: w.name,
          filename: w.path,
        }));
        setWalletList(mapped);
      })
      .catch(() => setWalletList([]));
  }, [setWalletList]);

  const handleOpen = (walletPath: string) => {
    setSelectedWallet(walletPath);
    setView('login');
  };

  const handleCreate = () => {
    setSelectedWallet(null);
    setView('login');
  };

  const languages: { code: Language; label: string; flag: string }[] = [
    { code: 'en', label: 'English', flag: '🇬🇧' },
    { code: 'de', label: 'Deutsch', flag: '🇩🇪' },
  ];

  return (
    <div className="flex h-screen items-center justify-center bg-void-950">
      <div className="w-96 max-w-sm">
        <div className="text-center mb-8">
          <div className="text-3xl font-bold text-accent mb-2">{t.landing.title}</div>
          <div className="text-sm text-gray-400">{t.landing.subtitle}</div>
        </div>

        <div className="bg-void-900 rounded-xl p-6 border border-void-700">
          {/* Wallet list */}
          <div className="text-xs text-gray-400 mb-2">{t.landing.yourWallets}</div>
          {walletList.length === 0 ? (
            <div className="text-sm text-gray-400 mb-4 italic">{t.landing.noWallets}</div>
          ) : (
            <div className="space-y-2 mb-4">
              {walletList.map((w) => (
                <div key={w.filename} className="flex items-center justify-between bg-void-800 rounded-lg px-3 py-2">
                  <span className="text-sm text-gray-100 truncate">{w.name}</span>
                  <button
                    onClick={() => handleOpen(w.filename)}
                    className="text-xs px-3 py-1 rounded-md bg-accent hover:bg-accent-hover text-white transition-colors"
                  >
                    {t.landing.open}
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Create new wallet */}
          <button
            onClick={handleCreate}
            className="w-full bg-void-800 hover:bg-void-700 border border-void-700 text-gray-100 rounded-lg px-4 py-2 text-sm font-medium transition-colors mb-3"
          >
            {t.landing.createNew}
          </button>
        </div>

        {/* Language selector */}
        <div className="mt-4 flex items-center justify-center gap-2">
          <span className="text-xs text-gray-500">{t.landing.language}:</span>
          {languages.map((lang) => (
            <button
              key={lang.code}
              onClick={() => setLanguage(lang.code)}
              className={`text-xs px-2 py-1 rounded transition-colors ${
                language === lang.code
                  ? 'bg-void-800 text-accent border border-void-700'
                  : 'text-gray-400 hover:text-gray-100'
              }`}
            >
              {lang.flag} {lang.label}
            </button>
          ))}
        </div>

        <div className="text-center mt-3 text-xs text-gray-400">
          {t.landing.footer}
        </div>
      </div>
    </div>
  );
}