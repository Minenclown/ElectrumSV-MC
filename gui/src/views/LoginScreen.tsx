// Login screen — wallet lifecycle: unlock existing wallet or create new one
// Three modes:
//   "login"  — Open existing wallet: name + password (+ TOTP code if enabled)
//   "create" — New wallet: name + password → show mnemonic → confirm mnemonic → main
import { useState, useEffect } from 'react';
import { useStore } from '../store';
import { api } from '../api';
import { useTranslation, interp } from '../i18n';

type Mode = 'login' | 'create';
type CreateStep = 'form' | 'mnemonic' | 'confirm';

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
      if (selectedWallet) {
        setMode('create');
      }
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
    setView('landing');
  };

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