// Login screen — wallet lifecycle: unlock existing wallet or create new one
// Three modes:
//   "login"  — Open existing wallet: name + password (+ TOTP code if enabled)
//   "create" — New wallet: name + password → show mnemonic → confirm mnemonic → main
import { useState, useEffect } from 'react';
import { useStore } from '../store';
import { api } from '../api';
import { useTranslation, interp } from '../i18n';

type Mode = 'login' | 'create' | 'restore';
type CreateStep = 'form' | 'mnemonic' | 'confirm';
type RestoreMethod = 'mnemonic' | 'wif' | null;

export function LoginScreen() {
  const { setAuthenticated, setWalletInfo, setAccounts, setActiveAccount,
           selectedWallet, setView, setActiveWalletPath,
           setWalletPassword } = useStore();
  const { t } = useTranslation();
  const [walletName, setWalletName] = useState(selectedWallet ?? '');
  const [walletPassword, setWalletPasswordState] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<Mode>(selectedWallet ? 'login' : 'create');

  const [totpRequired, setTotpRequired] = useState(false);
  const [totpCode, setTotpCode] = useState('');
  const [totpChecked, setTotpChecked] = useState(false);

  const [createStep, setCreateStep] = useState<CreateStep>('form');
  const [mnemonic, setMnemonic] = useState<string | null>(null);
  const [confirmInput, setConfirmInput] = useState('');

  // Restore state
  const [restoreMethod, setRestoreMethod] = useState<RestoreMethod>(null);
  const [restoreInput, setRestoreInput] = useState('');
  const [restoreName, setRestoreName] = useState('');
  const [restorePassword, setRestorePassword] = useState('');

  // Legacy ElectrumSV (1.3.x) migration state
  const [legacyMode, setLegacyMode] = useState(false);
  const [showLegacyWarning, setShowLegacyWarning] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const [legacyMigratedMnemonic, setLegacyMigratedMnemonic] = useState<string | null>(null);

  // In Tauri mode, the backend is always available (same process)
  const hasToken = true;

  useEffect(() => {
    if (mode !== 'login' || !selectedWallet) return;
    setTotpChecked(false);
    setTotpRequired(false);
  }, [mode, selectedWallet]);

  const handleLogin = async () => {
    setLoading(true);
    setError(null);
    try {
      const walletPath = selectedWallet
        ? `${selectedWallet}`
        : walletName;
      const openResult = await api.openWallet(walletPath);
      setActiveWalletPath(openResult.wallet_path);

      try {
        await api.unlockWalletWithTOTP(openResult.wallet_path, walletPassword, totpCode || undefined);
      } catch (e: any) {
        if (e.message && e.message.includes('TOTP code required')) {
          setTotpRequired(true);
          setTotpChecked(true);
          setLoading(false);
          return;
        }
        throw e;
      }
      setWalletPassword(walletPassword);

      const wi = await api.getWalletInfo();
      setWalletInfo({ walletName: wi.wallet_name ?? selectedWallet ?? '', walletLoaded: true });
      const accounts: any = await api.getAccounts();
      const accountList = Array.isArray(accounts) ? accounts : (accounts.accounts ?? []);
      const mapped = accountList.map((a: any) => ({
        id: a.account_id ?? a.id,
        name: a.account_name ?? a.name ?? '',
        type: 'standard',
      }));
      setAccounts(mapped);
      if (mapped.length > 0 && mapped[0].id !== undefined) {
        setActiveAccount(mapped[0].id);
      }
      setAuthenticated(true);
      useStore.getState().setView('main');
    } catch (e: any) {
      setError(e.message || t.login.loginFailed);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    setLoading(true);
    setError(null);
    try {
      const name = walletName.trim() || 'default_wallet';
      const result = await api.createWallet(walletPassword, name);
      setActiveWalletPath(result.wallet_path);
      setMnemonic(result.mnemonic);
      setCreateStep('mnemonic');
    } catch (e: any) {
      setError(e.message || t.login.createFailed);
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmMnemonic = () => {
    setError(null);
    if (confirmInput.trim().toLowerCase() === mnemonic?.trim().toLowerCase()) {
      loadWalletInfo();
    } else {
      setError(t.login.mnemonicMismatch);
    }
  };

  const handleSkipConfirm = () => {
    setError(null);
    loadWalletInfo();
  };

  const loadWalletInfo = async () => {
    setLoading(true);
    setError(null);
    try {
      const wi = await api.getWalletInfo();
      setWalletInfo({ walletName: wi.wallet_name ?? walletName, walletLoaded: true });
      const accounts: any = await api.getAccounts();
      const accountList = Array.isArray(accounts) ? accounts : (accounts.accounts ?? []);
      const mapped = accountList.map((a: any) => ({
        id: a.account_id ?? a.id,
        name: a.account_name ?? a.name ?? '',
        type: 'standard',
      }));
      setAccounts(mapped);
      if (mapped.length > 0 && mapped[0].id !== undefined) {
        setActiveAccount(mapped[0].id);
      }
      setWalletPassword(walletPassword);
      setAuthenticated(true);
      useStore.getState().setView('main');
    } catch (e: any) {
      setError(e.message || t.login.loadFailed);
    } finally {
      setLoading(false);
    }
  };

  const handleBack = () => {
    setCreateStep('form');
    setMnemonic(null);
    setConfirmInput('');
    setTotpRequired(false);
    setTotpCode('');
    setTotpChecked(false);
    setRestoreMethod(null);
    setRestoreInput('');
    setRestoreName('');
    setRestorePassword('');
    setLegacyMode(false);
    setShowLegacyWarning(false);
    setMigrating(false);
    setLegacyMigratedMnemonic(null);
    setView('landing');
  };

  const handleRestore = async () => {
    // Legacy mode: show warning dialog first instead of restoring directly
    if (restoreMethod === 'mnemonic' && legacyMode) {
      setShowLegacyWarning(true);
      return;
    }
    await doRestore();
  };

  const doRestore = async () => {
    setLoading(true);
    setError(null);
    try {
      const name = restoreName.trim() || 'restored_wallet';
      if (restoreMethod === 'mnemonic') {
        const result = await api.createWallet(restorePassword, name, restoreInput.trim());
        setActiveWalletPath(result.wallet_path);
        // Skip mnemonic display/confirm for restored wallets
        await loadWalletInfo();
      } else if (restoreMethod === 'wif') {
        // WIF import: create a new wallet, then import the key
        const result = await api.createWallet(restorePassword, name);
        setActiveWalletPath(result.wallet_path);
        await api.importPrivkey(restoreInput.trim(), restorePassword);
        await loadWalletInfo();
      }
    } catch (e: any) {
      setError(e.message || t.login.restoreInvalidMnemonic);
    } finally {
      setLoading(false);
    }
  };

  const handleLegacyMigrate = async () => {
    setShowLegacyWarning(false);
    setMigrating(true);
    setError(null);
    try {
      const name = restoreName.trim() || 'migrated_wallet';
      // Step 1: Create new BIP39 wallet from legacy seed
      const result = await api.restoreLegacyWallet(restoreInput.trim(), restorePassword, name);
      if (result?.wallet_path) {
        setActiveWalletPath(result.wallet_path);
      }
      // Step 2: Sweep legacy funds to the new wallet
      if (result?.wallet_path) {
        try {
          await api.sweepLegacyWallet(
            restoreInput.trim(), result.wallet_path, restorePassword
          );
        } catch (sweepErr: any) {
          // Sweep may fail if no UTXOs or network unavailable — non-fatal
          console.warn('sweep failed:', sweepErr?.message || sweepErr);
        }
      }
      // Step 3: Show the new BIP39 mnemonic for backup before proceeding
      if (result?.new_mnemonic) {
        setLegacyMigratedMnemonic(result.new_mnemonic);
      } else {
        // No mnemonic returned — proceed directly to wallet
        await loadWalletInfo();
      }
    } catch (e: any) {
      setError(e.message || t.login.restoreInvalidMnemonic);
    } finally {
      setMigrating(false);
    }
  };

  const handleLegacyMnemonicDone = async () => {
    setLegacyMigratedMnemonic(null);
    await loadWalletInfo();
  };

  // Restoration is a separate page. Sensitive values are entered only here,
  // never in the wallet selector/login screen.
  if (mode === 'restore') {
    const canRestore = Boolean(
      restoreMethod && restoreInput.trim() && restoreName.trim() && restorePassword.length >= 4,
    );

    // Legacy migration mnemonic display (after successful restoreLegacyWallet)
    if (legacyMigratedMnemonic) {
      return (
        <div className="flex h-screen items-center justify-center bg-void-950">
          <div className="w-full max-w-lg px-4">
            <div className="text-center mb-6">
              <div className="text-3xl font-bold text-accent mb-2">{t.login.legacyWarningTitle}</div>
              <div className="text-sm text-success">{t.login.legacyMigrationDone}</div>
            </div>
            <div className="bg-void-900 rounded-xl p-6 border border-void-700">
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4">
                <p className="text-xs text-red-400 font-medium">
                  {t.login.legacyNewMnemonic}
                </p>
              </div>
              <div className="bg-void-950 border border-void-700 rounded-lg p-4 mb-4">
                <div className="text-sm text-gray-100 font-mono leading-relaxed break-words select-all">
                  {legacyMigratedMnemonic}
                </div>
              </div>
              <button
                onClick={handleLegacyMnemonicDone}
                disabled={loading}
                className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
              >
                {loading ? t.common.loading : t.login.confirmOpen}
              </button>
              {error && <div className="text-sm text-danger mt-3">{error}</div>}
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="flex min-h-screen items-center justify-center bg-void-950 px-4 py-8">
        <div className="w-full max-w-lg">
          <div className="text-center mb-6">
            <div className="text-3xl font-bold text-accent mb-2">{t.login.restoreTitle}</div>
            <div className="text-sm text-gray-400">{t.login.restoreDesc}</div>
          </div>
          <div className="bg-void-900 rounded-xl p-6 border border-void-700">
            {!restoreMethod ? (
              <div className="space-y-3">
                <button onClick={() => setRestoreMethod('mnemonic')} className="w-full text-left rounded-lg border border-void-700 bg-void-800 hover:border-accent px-4 py-3 transition-colors">
                  <div className="text-sm font-medium text-gray-100">{t.login.restoreMnemonic}</div>
                  <div className="text-xs text-gray-400 mt-1">{t.login.restoreMnemonicDesc}</div>
                </button>
                <button onClick={() => setRestoreMethod('wif')} className="w-full text-left rounded-lg border border-void-700 bg-void-800 hover:border-accent px-4 py-3 transition-colors">
                  <div className="text-sm font-medium text-gray-100">{t.login.restoreWif}</div>
                  <div className="text-xs text-gray-400 mt-1">{t.login.restoreWifDesc}</div>
                </button>
              </div>
            ) : (
              <>
                <button onClick={() => { setRestoreMethod(null); setRestoreInput(''); setError(null); setLegacyMode(false); }} className="text-xs text-gray-400 hover:text-gray-100 mb-4 transition-colors">
                  ← {t.login.restoreDesc}
                </button>
                <label className="block text-xs text-gray-400 mb-1">{t.login.restoreNameLabel}</label>
                <input type="text" value={restoreName} onChange={(e) => setRestoreName(e.target.value)} placeholder="restored_wallet" className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3" />
                <label className="block text-xs text-gray-400 mb-1">{restoreMethod === 'mnemonic' ? t.login.restoreMnemonic : t.login.restoreWif}</label>
                <textarea value={restoreInput} onChange={(e) => setRestoreInput(e.target.value)} placeholder={restoreMethod === 'mnemonic' ? t.login.restoreMnemonicPlaceholder : t.login.restoreWifPlaceholder} className="w-full h-24 bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono focus:border-accent outline-none mb-3 resize-none" autoFocus spellCheck={false} />
                {restoreMethod === 'mnemonic' && (
                  <button
                    onClick={() => setLegacyMode(!legacyMode)}
                    className={`w-full rounded-lg border px-3 py-2 text-xs font-medium mb-3 transition-all ${
                      legacyMode
                        ? 'border-red-500 bg-red-500/10 text-red-400 shadow-[0_0_12px_rgba(239,68,68,0.3)]'
                        : 'border-void-700 text-gray-400 hover:border-gray-500'
                    }`}
                  >
                    {legacyMode ? '● ' : ''}{t.login.legacyToggle}
                  </button>
                )}
                <label className="block text-xs text-gray-400 mb-1">{t.login.restorePasswordLabel}</label>
                <input type="password" value={restorePassword} onChange={(e) => setRestorePassword(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && canRestore && handleRestore()} className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-4" />
                <button onClick={handleRestore} disabled={loading || migrating || !canRestore} className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                  {loading || migrating ? (legacyMode ? t.login.legacyMigrating : t.login.restoring) : t.login.restoreButton}
                </button>
              </>
            )}
            {error && <div className="text-sm text-danger mt-3">{error}</div>}
          </div>
          <button onClick={() => { setRestoreMethod(null); setRestoreInput(''); setError(null); setLegacyMode(false); setMode(selectedWallet ? 'login' : 'create'); }} className="w-full text-center text-xs text-gray-400 hover:text-gray-100 mt-4 transition-colors">
            {t.login.restoreCancel}
          </button>
        </div>

        {/* Legacy migration warning dialog */}
        {showLegacyWarning && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="w-full max-w-md mx-4 bg-void-900 rounded-xl border border-red-500/50 shadow-2xl">
              <div className="p-6">
                <div className="text-xl font-bold text-red-400 mb-4">{t.login.legacyWarningTitle}</div>
                <p className="text-sm text-gray-300 leading-relaxed mb-6">{t.login.legacyWarningBody}</p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowLegacyWarning(false)}
                    className="flex-1 rounded-lg border border-void-700 bg-void-800 text-gray-400 px-4 py-2 text-sm font-medium hover:text-gray-100 transition-colors"
                  >
                    {t.login.restoreCancel}
                  </button>
                  <button
                    onClick={handleLegacyMigrate}
                    className="flex-1 rounded-lg bg-red-600 hover:bg-red-700 text-white px-4 py-2 text-sm font-medium transition-colors"
                  >
                    {t.login.legacyMigrate}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Migration progress overlay */}
        {migrating && !showLegacyWarning && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
            <div className="bg-void-900 rounded-xl border border-void-700 px-8 py-6 flex flex-col items-center gap-4">
              <div className="w-8 h-8 border-2 border-accent border-t-transparent rounded-full animate-spin" />
              <div className="text-sm text-gray-300">{t.login.legacyMigrating}</div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // Mnemonic display step
  if (mode === 'create' && createStep === 'mnemonic' && mnemonic) {
    return (
      <div className="flex h-screen items-center justify-center bg-void-950">
        <div className="w-96 max-w-sm">
          <div className="text-center mb-6">
            <div className="text-3xl font-bold text-accent mb-2">{t.login.title}</div>
            <div className="text-sm text-gray-400">{t.login.backupSeed}</div>
          </div>

          <div className="bg-void-900 rounded-xl p-6 border border-void-700">
            <div className="bg-warning/10 border border-warning/30 rounded-lg p-3 mb-4">
              <p className="text-xs text-warning">
                {interp(t.login.backupWarning, { count: mnemonic.split(' ').length })}
              </p>
            </div>

            <div className="bg-void-950 border border-void-700 rounded-lg p-4 mb-4">
              <div className="text-xs text-gray-400 mb-2">{t.login.yourMnemonic}</div>
              <div className="text-sm text-gray-100 font-mono leading-relaxed break-words select-all">
                {mnemonic}
              </div>
            </div>

            <p className="text-xs text-gray-400 mb-3">
              {t.login.mnemonicNext}
            </p>

            <button
              onClick={() => setCreateStep('confirm')}
              className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors mb-2"
            >
              {t.login.writtenDown}
            </button>
            <button
              onClick={handleSkipConfirm}
              className="w-full text-xs text-gray-400 hover:text-gray-100 transition-colors"
            >
              {t.login.skipConfirm}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Mnemonic confirmation step
  if (mode === 'create' && createStep === 'confirm' && mnemonic) {
    return (
      <div className="flex h-screen items-center justify-center bg-void-950">
        <div className="w-96 max-w-sm">
          <div className="text-center mb-6">
            <div className="text-3xl font-bold text-accent mb-2">{t.login.title}</div>
            <div className="text-sm text-gray-400">{t.login.confirmSeed}</div>
          </div>

          <div className="bg-void-900 rounded-xl p-6 border border-void-700">
            <p className="text-xs text-gray-400 mb-3">
              {t.login.confirmDesc}
            </p>
            <textarea
              value={confirmInput}
              onChange={(e) => setConfirmInput(e.target.value)}
              placeholder={t.login.confirmPlaceholder}
              className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono focus:border-accent outline-none mb-3 h-24 resize-none"
              autoFocus
            />
            <button
              onClick={handleConfirmMnemonic}
              disabled={loading}
              className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors mb-2"
            >
              {loading ? t.common.loading : t.login.confirmOpen}
            </button>
            <button
              onClick={() => setCreateStep('mnemonic')}
              className="w-full text-xs text-gray-400 hover:text-gray-100 transition-colors"
            >
              {t.login.backToSeed}
            </button>
            {error && <div className="text-sm text-danger mt-3">{error}</div>}
          </div>
        </div>
      </div>
    );
  }

  // Normal login/create form
  return (
    <div className="flex h-screen items-center justify-center bg-void-950">
      <div className="w-96 max-w-sm">
        <div className="text-center mb-8">
          <div className="text-3xl font-bold text-accent mb-2">{t.login.title}</div>
          <div className="text-sm text-gray-400">{t.login.subtitle}</div>
        </div>

        <div className="bg-void-900 rounded-xl p-6 border border-void-700">
          <div className="flex items-center gap-2 mb-4 text-xs">
            <div className="w-2 h-2 rounded-full bg-success" />
            <span className="text-success">
              {t.login.apiTokenReady}
            </span>
          </div>

          <div className="flex gap-2 mb-4">
            <button
              onClick={() => setMode('login')}
              className={`flex-1 text-sm py-2 rounded-lg transition-colors ${
                mode === 'login' ? 'bg-void-800 text-accent' : 'text-gray-400 hover:text-gray-100'
              }`}
            >
              {t.login.unlockWallet}
            </button>
            <button
              onClick={() => setMode('create')}
              className={`flex-1 text-sm py-2 rounded-lg transition-colors ${
                mode === 'create' ? 'bg-void-800 text-accent' : 'text-gray-400 hover:text-gray-100'
              }`}
            >
              {t.login.newWallet}
            </button>
          </div>

          {mode === 'login' ? (
            <>
              <p className="text-xs text-gray-400 mb-3">
                {selectedWallet
                  ? `${t.login.unlockSelected}`
                  : t.login.enterNamePassword}
              </p>
              {!selectedWallet && (
                <input
                  type="text"
                  value={walletName}
                  onChange={(e) => setWalletName(e.target.value)}
                  placeholder={t.login.walletName}
                  className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3"
                  autoFocus
                />
              )}
              <input
                type="password"
                value={walletPassword}
                onChange={(e) => setWalletPasswordState(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && hasToken && walletPassword.length >= 4 && !totpRequired && handleLogin()}
                placeholder={t.login.walletPassword}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3"
                autoFocus={!!selectedWallet}
              />
              {totpRequired && (
                <div className="mb-3 p-3 bg-void-950 border border-warning/30 rounded-lg">
                  <div className="text-xs text-warning mb-2">
                    {t.login.totpRequired}
                  </div>
                  <input
                    type="text"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && totpCode.length === 6 && handleLogin()}
                    placeholder={t.login.totpPlaceholder}
                    maxLength={6}
                    className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none"
                    autoFocus
                  />
                </div>
              )}
              <button
                onClick={handleLogin}
                disabled={loading || !hasToken || (walletPassword.length < 4) || (totpRequired && totpCode.length !== 6)}
                className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? t.login.unlocking : totpRequired ? t.login.unlock2fa : t.login.unlockWallet}
              </button>
            </>
          ) : (
            <>
              <p className="text-xs text-gray-400 mb-3">
                {t.login.createDesc}
              </p>
              <input
                type="text"
                value={walletName}
                onChange={(e) => setWalletName(e.target.value)}
                placeholder={t.login.walletNamePlaceholder}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3"
                autoFocus
              />
              <input
                type="password"
                value={walletPassword}
                onChange={(e) => setWalletPasswordState(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && hasToken && walletName && walletPassword.length >= 4 && handleCreate()}
                placeholder={t.login.newPassword}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none mb-3"
              />
              <button
                onClick={handleCreate}
                disabled={loading || !hasToken || !walletName || walletPassword.length < 4}
                className="w-full bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? t.login.creating : t.login.createWallet}
              </button>
            </>
          )}

          <button
            onClick={() => { setMode('restore'); setRestoreMethod(null); setError(null); }}
            className="w-full mt-4 rounded-md border border-void-700 bg-void-950/60 px-3 py-2 text-xs text-gray-400 hover:border-accent hover:text-accent transition-colors"
          >
            {t.login.restoreWallet}
          </button>

          {error && <div className="text-sm text-danger mt-3">{error}</div>}
        </div>

        <button
          onClick={handleBack}
          className="w-full text-center text-xs text-gray-400 hover:text-gray-100 mt-4 transition-colors"
        >
          {t.login.backToWallets}
        </button>
      </div>
    </div>
  );
}