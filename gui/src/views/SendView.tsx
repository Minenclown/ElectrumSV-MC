// Send view — 3-stage BSV transaction workflow: Prepare → Preview → Sign → Broadcast
import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import { useStore } from '../store';

type SendStep = 'form' | 'preview' | 'result';

export function SendView() {
  const { activeAccountId, walletPassword, setPlanId } = useStore();
  const [step, setStep] = useState<SendStep>('form');
  const [address, setAddress] = useState('');
  const [resolvedAddress, setResolvedAddress] = useState<string | null>(null);
  const [amount, setAmount] = useState('');
  const [password, setPassword] = useState(walletPassword ?? '');
  const [opReturn, setOpReturn] = useState('');
  const [feeRate, setFeeRate] = useState(10);
  const [feeSourceMapi, setFeeSourceMapi] = useState(false);
  const [estimatedFee, setEstimatedFee] = useState<number | null>(null);
  // AUD-008: renderer only holds the plan_id handle + preview metadata.
  const [planId, setPlanIdState] = useState<string | null>(null);
  const [preview, setPreview] = useState<{
    fee: number;
    total_input: number;
    total_output: number;
    change: number;
    num_inputs: number;
    num_outputs: number;
  } | null>(null);
  const [signedTxHex, setSignedTxHex] = useState<string | null>(null);
  const [signedTxid, setSignedTxid] = useState<string | null>(null);
  const [txid, setTxid] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [contacts, setContacts] = useState<any[]>([]);

  // TOTP state — TOTP is mandatory in the Rust backend for sign_tx
  const [totpCode, setTotpCode] = useState('');
  const [totpEnabled, setTotpEnabled] = useState(false);

  // Multisig info (Task 5) — if the active account is a multisig account,
  // show a banner with the m-of-n threshold.
  const [multisigInfo, setMultisigInfo] = useState<{ threshold: number; num_keys: number } | null>(null);

  // Load contacts for recipient dropdown
  useEffect(() => {
    api.getContacts()
      .then((r: any[]) => setContacts(Array.isArray(r) ? r : []))
      .catch(() => setContacts([]));
  }, []);

  // Check TOTP status on mount
  useEffect(() => {
    api.getTotpStatus()
      .then(s => setTotpEnabled(s.enabled))
      .catch(() => setTotpEnabled(false));
  }, []);

  // Fetch multisig config for the active account (Task 5).
  // If the account is a multisig account, show a banner with the m-of-n info.
  useEffect(() => {
    if (activeAccountId === null) {
      setMultisigInfo(null);
      return;
    }
    let cancelled = false;
    api.getMultisigConfig(activeAccountId)
      .then(cfg => {
        if (cancelled) return;
        if (cfg && cfg.threshold && cfg.num_keys) {
          setMultisigInfo({ threshold: cfg.threshold, num_keys: cfg.num_keys });
        } else {
          setMultisigInfo(null);
        }
      })
      .catch(() => { if (!cancelled) setMultisigInfo(null); });
    return () => { cancelled = true; };
  }, [activeAccountId]);

  // Fetch mAPI fee quote on mount — if the user hasn't changed the default,
  // replace the fee rate with the mAPI mining fee (sat/byte). The user can
  // still adjust the slider manually afterwards.
  useEffect(() => {
    let cancelled = false;
    api.getMapiFeeQuote()
      .then(quote => {
        if (cancelled) return;
        // Only override if the user has not moved the slider away from default.
        if (quote.mining_fee_satoshis && quote.mining_fee_satoshis > 0) {
          setFeeRate(quote.mining_fee_satoshis);
          setFeeSourceMapi(true);
        }
      })
      .catch(() => {
        // mAPI unreachable — keep default fee rate, no badge.
        if (!cancelled) setFeeSourceMapi(false);
      });
    return () => { cancelled = true; };
  }, []);

  // Debounced fee estimation
  const estimateFee = useCallback(async (rate: number) => {
    if (!address || !amount) return;
    try {
      const r = await api.estimateFee(
        [{ address, satoshis: parseInt(amount, 10) || 0 }],
        rate,
        opReturn || undefined
      );
      setEstimatedFee(r.fee);
    } catch {
      setEstimatedFee(null);
    }
  }, [address, amount, opReturn]);

  useEffect(() => {
    const timer = setTimeout(() => estimateFee(feeRate), 400);
    return () => clearTimeout(timer);
  }, [feeRate, estimateFee]);

  const resetForm = () => {
    setStep('form');
    setAddress('');
    setResolvedAddress(null);
    setAmount('');
    setOpReturn('');
    setPlanIdState(null);
    setPreview(null);
    setSignedTxHex(null);
    setSignedTxid(null);
    setTxid(null);
    setStatus(null);
    setTotpCode('');
    setPlanId(null);
  };

  // Step 1: Prepare transaction
  const handlePrepare = async () => {
    if (activeAccountId === null) return;
    setBusy(true);
    setStatus(null);
    try {
      // Resolve PayMail handle if the address contains '@'
      let resolvedAddr = address.trim();
      if (resolvedAddr.includes('@')) {
        setStatus('Resolving PayMail handle…');
        try {
          const result = await api.resolvePaymail(resolvedAddr);
          resolvedAddr = result.address;
          setResolvedAddress(resolvedAddr);
        } catch (e: any) {
          setStatus(`PayMail resolution failed: ${e.message || e}`);
          setBusy(false);
          return;
        }
      } else {
        setResolvedAddress(null);
      }
      const outputs = [{ address: resolvedAddr, satoshis: parseInt(amount, 10) }];
      const r = await api.prepareTx({
        outputs,
        feeRate,
        opReturn: opReturn || undefined,
      });
      setPlanIdState(r.plan_id);
      setPlanId(r.plan_id);
      setPreview({
        fee: r.fee,
        total_input: r.total_input,
        total_output: r.total_output,
        change: r.change,
        num_inputs: r.num_inputs,
        num_outputs: r.num_outputs,
      });
      setStep('preview');
    } catch (e: any) {
      setStatus(`Error: ${e.message || e}`);
    } finally {
      setBusy(false);
    }
  };

  // Step 2: Sign (requires TOTP code)
  const handleSign = async () => {
    if (!planId) return;
    if (totpEnabled && totpCode.length !== 6) {
      setStatus('TOTP code required (6 digits).');
      return;
    }
    setBusy(true);
    setStatus(null);
    try {
      const signResult = await api.signTx(planId, totpCode);
      setSignedTxHex(signResult.signed_tx_hex);
      setSignedTxid(signResult.txid);
      setStatus('Transaction signed. Ready to broadcast.');
    } catch (e: any) {
      setStatus(`Error: ${e.message || e}`);
    } finally {
      setBusy(false);
    }
  };

  // Step 3: Broadcast
  const handleBroadcast = async () => {
    if (!signedTxHex || !signedTxid) return;
    setBusy(true);
    setStatus(null);
    try {
      const resultTxid = await api.broadcastTx(signedTxHex, signedTxid);
      setTxid(resultTxid);
      setStep('result');
      setStatus('Transaction broadcast successfully!');
    } catch (e: any) {
      setStatus(`Error: ${e.message || e}`);
    } finally {
      setBusy(false);
    }
  };

  const canPrepare = address && amount && parseInt(amount, 10) > 0 && activeAccountId !== null;
  const canSign = planId && totpEnabled && totpCode.length === 6;
  const canBroadcast = signedTxHex && signedTxid;

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold mb-4 text-accent">Send BSV</h2>

      {/* Multisig account banner (Task 5) */}
      {multisigInfo && (
        <div className="mb-4 bg-void-900 border border-accent/40 rounded-lg p-3 text-sm">
          <span className="text-accent font-medium">
            🔑 Multisig Account ({multisigInfo.threshold}-of-{multisigInfo.num_keys})
          </span>
          <span className="text-gray-400 ml-2">
            This account requires {multisigInfo.threshold} of {multisigInfo.num_keys} signatures to spend.
          </span>
        </div>
      )}

      {/* Step indicator */}
      <div className="flex items-center gap-2 mb-6 text-sm">
        <span className={step === 'form' ? 'text-accent' : 'text-gray-400'}>1. Form</span>
        <span className="text-gray-400">→</span>
        <span className={step === 'preview' ? 'text-accent' : 'text-gray-400'}>2. Preview & Sign</span>
        <span className="text-gray-400">→</span>
        <span className={step === 'result' ? 'text-accent' : 'text-gray-400'}>3. Result</span>
      </div>

      <div className="space-y-3 max-w-lg">
        {/* ─── Step 1: Form ─── */}
        {step === 'form' && (
          <>
            {/* Contact shortcut */}
            {contacts.length > 0 && (
              <div>
                <label className="text-sm text-gray-400 mb-1 block">From contacts</label>
                <select
                  onChange={(e) => {
                    const c = contacts.find((c) => String(c.contact_id) === e.target.value);
                    if (c) {
                      const addr = c.identities?.[0]?.system_data || '';
                      setAddress(addr);
                    }
                  }}
                  className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
                >
                  <option value="">— select contact —</option>
                  {contacts.map((c) => (
                    <option key={c.contact_id} value={c.contact_id}>
                      {c.label}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div>
              <label className="text-sm text-gray-400 mb-1 block">Recipient address or PayMail</label>
              <input
                type="text"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or user@domain.com"
                className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
              />
            </div>

            <div>
              <label className="text-sm text-gray-400 mb-1 block">Amount (satoshis)</label>
              <input
                type="number"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="1000"
                className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
              />
            </div>

            {/* Fee slider */}
            <div>
              <label className="text-sm text-gray-400 mb-1 block">
                Fee rate: {feeRate} sat/byte
                {feeSourceMapi && (
                  <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-accent/20 text-accent border border-accent/40">
                    mAPI
                  </span>
                )}
                {estimatedFee !== null && (
                  <span className="text-gray-400 ml-2">≈ {estimatedFee} sat total</span>
                )}
              </label>
              <input
                type="range"
                min="1"
                max="50"
                value={feeRate}
                onChange={(e) => { setFeeRate(parseInt(e.target.value, 10)); setFeeSourceMapi(false); }}
                className="w-full accent-accent"
              />
              <div className="flex justify-between text-xs text-gray-400 mt-1">
                <span>1 (slow)</span>
                <span>10 (default)</span>
                <span>50 (fast)</span>
              </div>
            </div>

            {/* OP_RETURN */}
            <div>
              <label className="text-sm text-gray-400 mb-1 block">
                OP_RETURN <span className="text-gray-400">(optional — hex or text)</span>
              </label>
              <input
                type="text"
                value={opReturn}
                onChange={(e) => setOpReturn(e.target.value)}
                placeholder="e.g. hello world or 48656c6c6f"
                className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
              />
            </div>

            <div>
              <label className="text-sm text-gray-400 mb-1 block">Wallet password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-void-900 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
              />
            </div>

            <button
              onClick={handlePrepare}
              disabled={busy || !canPrepare}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {busy ? 'Preparing…' : 'Prepare Transaction'}
            </button>
          </>
        )}

        {/* ─── Step 2: Preview & Sign ─── */}
        {step === 'preview' && planId && preview && (
          <>
            <div className="bg-void-900 border border-void-700 rounded-lg p-4 space-y-2">
              <div className="text-sm font-semibold text-accent mb-2">Transaction Preview</div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">To</span>
                <span className="font-mono text-gray-300">{address.slice(0, 24)}…</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Amount</span>
                <span className="text-gray-100">{parseInt(amount).toLocaleString()} sat</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Fee ({feeRate} sat/byte)</span>
                <span className="text-gray-100">{preview.fee} sat</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Change</span>
                <span className="text-gray-100">{preview.change} sat</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Inputs</span>
                <span className="text-gray-100">{preview.num_inputs}</span>
              </div>
              <div className="border-t border-void-700 pt-2 flex justify-between text-sm font-semibold">
                <span className="text-gray-400">Total Input</span>
                <span className="text-accent">{preview.total_input.toLocaleString()} sat</span>
              </div>
              {opReturn && (
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">OP_RETURN</span>
                  <span className="font-mono text-gray-300 text-xs">{opReturn.slice(0, 32)}…</span>
                </div>
              )}
            </div>

            {/* TOTP code input — always shown because sign_tx requires it */}
            <div className="bg-void-900 border border-warning/30 rounded-lg p-3">
              <div className="text-xs text-warning mb-2">
                🔒 TOTP code required to sign this transaction.
              </div>
              {!totpEnabled && (
                <div className="text-xs text-danger mb-2">
                  ⚠ TOTP must be enabled to sign. Enable 2FA in the Security tab first.
                </div>
              )}
              <input
                type="text"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                placeholder="6-digit TOTP code"
                maxLength={6}
                disabled={!totpEnabled}
                className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono text-center focus:border-accent outline-none disabled:opacity-50"
              />
            </div>

            {/* Signed TX info */}
            {signedTxHex && (
              <div className="bg-void-900 border border-success/30 rounded-lg p-3">
                <div className="text-xs text-success mb-1">✓ Signed successfully</div>
                <div className="text-xs text-gray-400">TXID: <span className="font-mono text-gray-300">{signedTxid}</span></div>
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={() => { setStep('form'); setPlanIdState(null); setPreview(null); setSignedTxHex(null); setSignedTxid(null); }}
                disabled={busy}
                className="bg-void-800 hover:bg-void-700 text-gray-300 rounded-lg px-4 py-2 text-sm font-medium transition-colors"
              >
                ← Back
              </button>
              {!signedTxHex ? (
                <button
                  onClick={handleSign}
                  disabled={busy || !canSign}
                  className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {busy ? 'Signing…' : 'Sign Transaction'}
                </button>
              ) : (
                <button
                  onClick={handleBroadcast}
                  disabled={busy || !canBroadcast}
                  className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {busy ? 'Broadcasting…' : 'Broadcast Transaction'}
                </button>
              )}
            </div>
          </>
        )}

        {/* ─── Step 3: Result ─── */}
        {step === 'result' && (
          <>
            <div className="bg-void-900 border border-success rounded-lg p-4 space-y-2">
              <div className="text-sm font-semibold text-success">✓ Transaction Broadcast</div>
              {txid && (
                <div>
                  <div className="text-xs text-gray-400 mb-1">TXID</div>
                  <div className="font-mono text-sm text-gray-300 break-all">{txid}</div>
                </div>
              )}
            </div>
            <button
              onClick={resetForm}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors"
            >
              Send Another
            </button>
          </>
        )}

        {/* Status / errors */}
        {status && step !== 'result' && (
          <div className="text-sm text-error mt-2">{status}</div>
        )}
      </div>
    </div>
  );
}