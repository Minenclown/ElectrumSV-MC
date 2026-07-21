// SecurityView — per-wallet TOTP (2FA) management + Hardware wallet toggle
//
// Rust backend model (simplified):
//   enable_totp() → { otpauth_url, secret_base32 }  (one-step: generates & stores secret)
//   disable_totp() → ()
//   verify_totp(code) → bool
//   is_totp_enabled_cmd() → bool
//
// No scope concept, no recovery codes in current Rust backend.
// QR code generated via PicQr Rust backend (replaces qrcode npm package).
import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import { useStore } from '../store';

type SetupStep = 'idle' | 'qr' | 'verify';

export function SecurityView() {
  const { walletPassword } = useStore();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // TOTP status
  const [totpEnabled, setTotpEnabled] = useState(false);

  // Setup wizard
  const [setupStep, setSetupStep] = useState<SetupStep>('idle');
  const [setupSecret, setSetupSecret] = useState('');
  const [setupQrSvg, setSetupQrSvg] = useState<string | null>(null);
  const [setupCode, setSetupCode] = useState('');

  // Disable dialog
  const [disableCode, setDisableCode] = useState('');

  // Recovery codes
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [recoveryCodeInput, setRecoveryCodeInput] = useState('');
  const [recoveryLoading, setRecoveryLoading] = useState(false);

  // Hardware wallet
  const [hwEnabled, setHwEnabled] = useState(false);
  const [hwLoading, setHwLoading] = useState(false);

  // TOTP scope
  const [totpScope, setTotpScope] = useState('tx');
  const [scopeLoading, setScopeLoading] = useState(false);
  const [scopeCode, setScopeCode] = useState('');
  const [scopePassword, setScopePassword] = useState('');

  const generateQR = useCallback(async (uri: string) => {
    try {
      const result = await api.generateQr(uri, {
        scale: 10,
        quietZone: 4,
        ecLevel: 'M',
      });
      setSetupQrSvg(result.svg);
    } catch {
      setSetupQrSvg(null);
    }
  }, []);

  // Load TOTP + HW status on mount
  useEffect(() => {
    loadTotpStatus();
    loadHwStatus();
  }, []);

  const loadTotpStatus = async () => {
    try {
      const result = await api.getTotpStatus();
      setTotpEnabled(result.enabled);
    } catch {
      // Ignore — might not have a wallet loaded
    }
    try {
      const status = await api.getTotpStatus();
      setTotpScope(status.scope);
    } catch {
      // Ignore — use default 'tx'
    }
  };

  const loadHwStatus = async () => {
    try {
      const status = await api.getHardwareWalletStatus();
      setHwEnabled(status);
    } catch {
      // Ignore
    }
  };

  // ─── TOTP Enable (one-step: backend generates secret & stores it) ───
  const handleSetupStart = async () => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    setSetupQrSvg(null);
    try {
      const result = await api.totpEnable();
      setSetupSecret(result.secret_base32);
      await generateQR(result.otpauth_url);
      setSetupStep('qr');
    } catch (e: any) {
      setError(e.message || 'TOTP setup failed');
    } finally {
      setLoading(false);
    }
  };

  // ─── TOTP Verify (confirm code works, then mark as enabled) ───
  const handleSetupVerify = async () => {
    setLoading(true);
    setError(null);
    try {
      const valid = await api.verifyTotp(setupCode);
      if (valid) {
        setTotpEnabled(true);
        setSetupStep('idle');
        setSetupSecret('');
        setSetupQrSvg(null);
        setSetupCode('');
        setSuccess('2FA enabled successfully! Your wallet now requires a TOTP code for transactions.');
      } else {
        setError('Invalid TOTP code. Please try again.');
      }
    } catch (e: any) {
      setError(e.message || 'TOTP verification failed');
    } finally {
      setLoading(false);
    }
  };

  // ─── TOTP Disable ───
  const handleDisable = async () => {
    setLoading(true);
    setError(null);
    try {
      // Verify the code first before disabling
      if (disableCode) {
        const valid = await api.verifyTotp(disableCode);
        if (!valid) {
          setError('Invalid TOTP code. Cannot disable without verification.');
          setLoading(false);
          return;
        }
      }
      await api.totpDisable();
      setTotpEnabled(false);
      setDisableCode('');
      setRecoveryCodes(null);
      setSuccess('2FA disabled.');
    } catch (e: any) {
      setError(e.message || 'Disable failed');
    } finally {
      setLoading(false);
    }
  };

  // ─── Generate Recovery Codes ───
  const handleGenerateRecoveryCodes = async () => {
    setRecoveryLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const codes = await api.generateTotpRecoveryCodes();
      setRecoveryCodes(codes);
      setSuccess('Recovery codes generated. Save them now — they won\'t be shown again!');
    } catch (e: any) {
      setError(e.message || 'Failed to generate recovery codes');
    } finally {
      setRecoveryLoading(false);
    }
  };

  // ─── Recover Access with Recovery Code ───
  const handleRecover = async () => {
    setRecoveryLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const success = await api.totpRecover(recoveryCodeInput);
      if (success) {
        setTotpEnabled(false);
        setRecoveryCodeInput('');
        setRecoveryCodes(null);
        setDisableCode('');
        setSuccess('Access recovered! 2FA has been disabled. You can re-enable it if desired.');
      } else {
        setError('Invalid or already used recovery code.');
      }
    } catch (e: any) {
      setError(e.message || 'Recovery failed');
    } finally {
      setRecoveryLoading(false);
    }
  };

  // ─── TOTP Scope change ───
  const handleScopeChange = async (newScope: string) => {
    setScopeLoading(true);
    setError(null);
    setSuccess(null);
    try {
      await api.setTotpScope(scopePassword || walletPassword || '', newScope, scopeCode || undefined);
      setTotpScope(newScope);
      setScopeCode('');
      setScopePassword('');
      setSuccess(`TOTP scope changed to: ${newScope === 'tx' ? 'Every transaction' : 'Login only'}`);
    } catch (e: any) {
      setError(e.message || 'Failed to change TOTP scope');
    } finally {
      setScopeLoading(false);
    }
  };

  // ─── Hardware wallet toggle ───
  const handleHwToggle = async () => {
    setHwLoading(true);
    setError(null);
    try {
      await api.setHardwareWalletEnabled(!hwEnabled);
      setHwEnabled(!hwEnabled);
      setSuccess(`Hardware wallet ${!hwEnabled ? 'enabled' : 'disabled'}.`);
    } catch (e: any) {
      setError(e.message || 'Hardware wallet toggle failed');
    } finally {
      setHwLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-2xl mx-auto">
      <h2 className="text-xl font-semibold text-accent mb-6">Security Settings</h2>

      {/* Status card */}
      <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm text-gray-400">Current Protection</span>
          <span className={`text-sm font-medium ${totpEnabled ? 'text-success' : 'text-warning'}`}>
            {totpEnabled ? '● Password + 2FA (TX)' : '● Password only'}
          </span>
        </div>
        <p className="text-xs text-gray-400">
          {totpEnabled
            ? 'Your wallet is protected with two-factor authentication. A TOTP code is required for every transaction.'
            : 'Your wallet uses password-only protection. Consider enabling 2FA for additional security.'}
        </p>
      </div>

      {/* Hardware Wallet card */}
      <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-100 mb-1">Hardware Wallet</h3>
            <p className="text-xs text-gray-400">
              {hwEnabled
                ? 'Hardware wallet signing is enabled. Transactions will be signed by your connected device.'
                : 'Software-only signing. Enable to use a hardware wallet for signing transactions.'}
            </p>
          </div>
          <button
            onClick={handleHwToggle}
            disabled={hwLoading}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              hwEnabled ? 'bg-accent' : 'bg-void-700'
            } disabled:opacity-50`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                hwEnabled ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </div>

      {/* TOTP Scope — shown when TOTP is enabled */}
      {totpEnabled && (
        <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 className="text-sm font-medium text-gray-100 mb-3">TOTP Scope</h3>
          <p className="text-xs text-gray-400 mb-3">
            Current scope: <span className="text-gray-100 font-medium">
              {totpScope === 'tx' ? 'Every transaction (max security)' : 'Login only'}
            </span>
            <br />
            {totpScope === 'tx'
              ? 'A TOTP code is required for every transaction AND at login.'
              : 'A TOTP code is only required at login. Transactions do not need TOTP.'}
          </p>
          <div className="space-y-2">
            <input
              type="password"
              value={scopePassword}
              onChange={(e) => setScopePassword(e.target.value)}
              placeholder="Wallet password (or use stored password)"
              className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
            />
            {totpScope === 'tx' && (
              <input
                type="text"
                value={scopeCode}
                onChange={(e) => setScopeCode(e.target.value)}
                placeholder="Current TOTP code (required to lower scope)"
                maxLength={6}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none"
              />
            )}
            <div className="flex gap-2">
              {totpScope === 'tx' && (
                <button
                  onClick={() => handleScopeChange('login')}
                  disabled={scopeLoading}
                  className="flex-1 bg-void-800 hover:bg-void-700 text-gray-100 rounded-lg px-3 py-2 text-xs font-medium border border-void-700 disabled:opacity-50 transition-colors"
                >
                  {scopeLoading ? '…' : 'Lower to Login-only'}
                </button>
              )}
              {totpScope === 'login' && (
                <button
                  onClick={() => handleScopeChange('tx')}
                  disabled={scopeLoading}
                  className="flex-1 bg-accent hover:bg-accent-hover text-white rounded-lg px-3 py-2 text-xs font-medium disabled:opacity-50 transition-colors"
                >
                  {scopeLoading ? '…' : 'Raise to Every-TX'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {error && <div className="text-sm text-danger mb-4 p-3 bg-danger/10 rounded-lg">{error}</div>}
      {success && <div className="text-sm text-success mb-4 p-3 bg-success/10 rounded-lg">{success}</div>}

      {/* Enable 2FA — Setup Wizard */}
      {!totpEnabled && setupStep === 'idle' && (
        <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 className="text-sm font-medium text-gray-100 mb-3">Enable 2FA (TOTP)</h3>
          <p className="text-xs text-gray-400 mb-4">
            Add an extra layer of security with your authenticator app
            (Google Authenticator, Authy, FreeOTP). A TOTP code will be
            required for every transaction you sign.
          </p>
          <button
            onClick={handleSetupStart}
            disabled={loading || !walletPassword}
            className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {loading ? 'Starting…' : 'Set up 2FA'}
          </button>
          {!walletPassword && (
            <p className="text-xs text-warning mt-2">Wallet password required (unlock wallet first)</p>
          )}
        </div>
      )}

      {/* Setup — QR code step */}
      {setupStep === 'qr' && (
        <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 className="text-sm font-medium text-gray-100 mb-3">Scan QR Code</h3>
          <p className="text-xs text-gray-400 mb-3">
            Scan with your 2FA app, or enter the secret manually.
          </p>
          {setupQrSvg && (
            <div className="flex justify-center mb-4">
              <div className="w-48 h-48 rounded-lg bg-white p-1" dangerouslySetInnerHTML={{ __html: setupQrSvg }} />
            </div>
          )}
          <div className="mb-3">
            <span className="text-xs text-gray-400">Secret: </span>
            <span className="text-xs font-mono text-gray-300 select-all">{setupSecret}</span>
          </div>

          {/* Code verification */}
          <input
            type="text"
            value={setupCode}
            onChange={(e) => setSetupCode(e.target.value)}
            placeholder="Enter 6-digit code from your app"
            maxLength={6}
            className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none mb-3"
          />
          <div className="flex gap-2">
            <button
              onClick={handleSetupVerify}
              disabled={loading || setupCode.length !== 6}
              className="flex-1 bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
            >
              {loading ? 'Verifying…' : 'Verify & Enable'}
            </button>
            <button
              onClick={() => { setSetupStep('idle'); setSetupQrSvg(null); setSetupSecret(''); setSetupCode(''); setError(null); }}
              className="text-sm text-gray-400 hover:text-gray-100 px-4 py-2"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Disable 2FA */}
      {totpEnabled && (
        <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 className="text-sm font-medium text-gray-100 mb-3">Disable 2FA</h3>
          <p className="text-xs text-gray-400 mb-3">
            Enter your current TOTP code to verify, then disable 2FA.
          </p>
          <input
            type="text"
            value={disableCode}
            onChange={(e) => setDisableCode(e.target.value)}
            placeholder="Current 6-digit TOTP code"
            maxLength={6}
            className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none mb-3"
          />
          <button
            onClick={handleDisable}
            disabled={loading || disableCode.length !== 6}
            className="bg-void-800 text-danger hover:bg-void-700 border border-danger/30 rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {loading ? 'Disabling…' : 'Disable 2FA'}
          </button>
        </div>
      )}

      {/* Recovery Codes — shown when TOTP is enabled */}
      {totpEnabled && (
        <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
          <h3 className="text-sm font-medium text-gray-100 mb-3">Recovery Codes</h3>
          <p className="text-xs text-gray-400 mb-4">
            Generate one-time recovery codes to regain access if you lose your
            authenticator device. Store them in a safe place — each code can only
            be used once.
          </p>

          {/* Generate button */}
          {!recoveryCodes && (
            <button
              onClick={handleGenerateRecoveryCodes}
              disabled={recoveryLoading}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
            >
              {recoveryLoading ? 'Generating…' : 'Generate Recovery Codes'}
            </button>
          )}

          {/* Display codes one-time */}
          {recoveryCodes && (
            <div>
              <div className="mb-3 p-3 bg-warning/10 rounded-lg border border-warning/30">
                <p className="text-xs text-warning font-medium">
                  ⚠ Save these codes now — they will not be shown again!
                </p>
              </div>
              <div className="grid grid-cols-2 gap-2 mb-4">
                {recoveryCodes.map((code, idx) => (
                  <div
                    key={idx}
                    className="bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm font-mono text-gray-100 text-center select-all"
                  >
                    {code}
                  </div>
                ))}
              </div>
              <button
                onClick={() => setRecoveryCodes(null)}
                className="text-sm text-gray-400 hover:text-gray-100 transition-colors"
              >
                I've saved my codes — dismiss
              </button>
            </div>
          )}
        </div>
      )}

      {/* Recover Access — always visible (for lost device scenario) */}
      <div className="bg-void-900 rounded-xl p-5 border border-void-700 mb-6">
        <h3 className="text-sm font-medium text-gray-100 mb-3">Recover Access</h3>
        <p className="text-xs text-gray-400 mb-3">
          Lost access to your authenticator? Enter a recovery code to disable 2FA
          and regain full access to your wallet.
        </p>
        <input
          type="text"
          value={recoveryCodeInput}
          onChange={(e) => setRecoveryCodeInput(e.target.value.toUpperCase())}
          placeholder="XXXX-XXXX"
          className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none mb-3"
        />
        <button
          onClick={handleRecover}
          disabled={recoveryLoading || recoveryCodeInput.length === 0}
          className="bg-void-800 text-warning hover:bg-void-700 border border-warning/30 rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 transition-colors"
        >
          {recoveryLoading ? 'Recovering…' : 'Recover Access'}
        </button>
      </div>
    </div>
  );
}