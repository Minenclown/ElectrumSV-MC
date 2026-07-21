// ServicesView — SPV Channels, Cosigner Pool, Label Sync
//
// Minimal dark-mode UI exposing the three network service backends.
// The main purpose is to make the backend Tauri commands accessible:
// input fields for server URL, action buttons, and raw JSON result display.
// Not a polished production UI — just a functional surface.

import { useState } from 'react';
import { api } from '../api';

type ServiceTab = 'spv' | 'cosigner' | 'labelsync';

// ─── Shared small components ───────────────────────────────────────────

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-void-900 rounded-lg p-4 border border-void-700">
      <div className="text-sm font-semibold text-gray-200 mb-3">{title}</div>
      {children}
    </div>
  );
}

function Label({ text }: { text: string }) {
  return <label className="block text-xs text-gray-400 mb-1">{text}</label>;
}

function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`w-full bg-void-800 text-gray-100 text-sm rounded-lg px-3 py-2 border border-void-700 focus:border-accent focus:outline-none transition-colors ${props.className ?? ''}`}
    />
  );
}

function Button({
  onClick,
  disabled,
  children,
  variant = 'primary',
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'danger';
}) {
  const base = 'rounded-lg px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50';
  const styles =
    variant === 'primary'
      ? 'bg-accent hover:bg-accent-hover text-white'
      : variant === 'danger'
        ? 'border border-danger/30 text-danger hover:text-red-400'
        : 'bg-void-800 hover:bg-void-700 text-gray-100 border border-void-700';
  return (
    <button onClick={onClick} disabled={disabled} className={`${base} ${styles}`}>
      {children}
    </button>
  );
}

function ResultBox({ data, error }: { data: any; error: string | null }) {
  if (error) return <div className="text-sm text-danger mt-2 p-3 bg-danger/10 rounded-lg break-all">{error}</div>;
  if (data === null || data === undefined) return null;
  return (
    <pre className="mt-2 text-xs text-gray-300 font-mono overflow-x-auto bg-void-950 p-3 rounded-lg border border-void-700 max-h-64 overflow-y-auto">
      {typeof data === 'string' ? data : JSON.stringify(data, null, 2)}
    </pre>
  );
}

// ─── SPV Channels section ──────────────────────────────────────────────

function SpvChannelsSection() {
  const [baseUrl, setBaseUrl] = useState('https://channels.example.com');
  const [publicKey, setPublicKey] = useState('');
  const [channelId, setChannelId] = useState('');
  const [encryptedPayload, setEncryptedPayload] = useState('');
  const [messageId, setMessageId] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<any>) => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await fn();
      setResult(r ?? 'OK');
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Section title="Create Channel">
        <div className="grid grid-cols-1 gap-3">
          <div>
            <Label text="Relay Base URL" />
            <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          </div>
          <div>
            <Label text="Public Key (hex)" />
            <Input value={publicKey} onChange={(e) => setPublicKey(e.target.value)} placeholder="02deadbeef..." />
          </div>
          <Button onClick={() => run(() => api.spvCreateChannel(baseUrl, publicKey))} disabled={busy || !publicKey}>
            Create Channel
          </Button>
        </div>
      </Section>

      <Section title="List / Send / Mark Read / Delete">
        <div className="grid grid-cols-1 gap-3">
          <div>
            <Label text="Channel ID" />
            <Input value={channelId} onChange={(e) => setChannelId(e.target.value)} />
          </div>
          <div className="flex gap-2 flex-wrap">
            <Button onClick={() => run(() => api.spvListMessages(baseUrl, channelId))} disabled={busy || !channelId} variant="secondary">
              List Messages
            </Button>
            <Button onClick={() => run(() => api.spvDeleteChannel(baseUrl, channelId))} disabled={busy || !channelId} variant="danger">
              Delete Channel
            </Button>
          </div>
          <div>
            <Label text="Encrypted Payload (base64)" />
            <Input value={encryptedPayload} onChange={(e) => setEncryptedPayload(e.target.value)} placeholder="base64-encoded ciphertext" />
          </div>
          <Button onClick={() => run(() => api.spvPostMessage(baseUrl, channelId, encryptedPayload))} disabled={busy || !channelId || !encryptedPayload}>
            Post Message
          </Button>
          <div>
            <Label text="Message ID (to mark read)" />
            <Input value={messageId} onChange={(e) => setMessageId(e.target.value)} />
          </div>
          <Button onClick={() => run(() => api.spvMarkRead(baseUrl, channelId, messageId))} disabled={busy || !channelId || !messageId} variant="secondary">
            Mark Read
          </Button>
        </div>
      </Section>

      <ResultBox data={result} error={error} />
    </div>
  );
}

// ─── Cosigner Pool section ─────────────────────────────────────────────

function CosignerPoolSection() {
  const [baseUrl, setBaseUrl] = useState('https://pool.example.com');
  const [walletId, setWalletId] = useState('');
  const [txid, setTxid] = useState('');
  const [txHex, setTxHex] = useState('');
  const [signers, setSigners] = useState('');
  const [requiredSigs, setRequiredSigs] = useState(2);
  const [totalCosigners, setTotalCosigners] = useState(3);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (fn: () => Promise<any>) => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await fn();
      setResult(r ?? 'OK');
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Section title="Pending Transactions">
        <div className="grid grid-cols-1 gap-3">
          <div>
            <Label text="Pool Base URL" />
            <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          </div>
          <div>
            <Label text="Wallet ID" />
            <Input value={walletId} onChange={(e) => setWalletId(e.target.value)} />
          </div>
          <Button onClick={() => run(() => api.cosignerGetPending(baseUrl, walletId))} disabled={busy || !walletId} variant="secondary">
            Get Pending
          </Button>
        </div>
      </Section>

      <Section title="Submit Partially Signed TX">
        <div className="grid grid-cols-1 gap-3">
          <div>
            <Label text="Wallet ID" />
            <Input value={walletId} onChange={(e) => setWalletId(e.target.value)} />
          </div>
          <div>
            <Label text="TXID" />
            <Input value={txid} onChange={(e) => setTxid(e.target.value)} />
          </div>
          <div>
            <Label text="TX Hex" />
            <Input value={txHex} onChange={(e) => setTxHex(e.target.value)} placeholder="01000000..." />
          </div>
          <div>
            <Label text="Signers (comma-separated)" />
            <Input value={signers} onChange={(e) => setSigners(e.target.value)} placeholder="alice,bob" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label text="Required Sigs (m)" />
              <Input
                type="number"
                value={requiredSigs}
                onChange={(e) => setRequiredSigs(Number(e.target.value))}
              />
            </div>
            <div>
              <Label text="Total Cosigners (n)" />
              <Input
                type="number"
                value={totalCosigners}
                onChange={(e) => setTotalCosigners(Number(e.target.value))}
              />
            </div>
          </div>
          <Button
            onClick={() =>
              run(() =>
                api.cosignerSubmitTx(baseUrl, {
                  wallet_id: walletId,
                  txid,
                  tx_hex: txHex,
                  signers: signers.split(',').map((s) => s.trim()).filter(Boolean),
                  required_sigs: requiredSigs,
                  total_cosigners: totalCosigners,
                }),
              )
            }
            disabled={busy || !walletId || !txid || !txHex}
          >
            Submit TX
          </Button>
          <Button onClick={() => run(() => api.cosignerDeleteTx(baseUrl, walletId, txid))} disabled={busy || !walletId || !txid} variant="danger">
            Delete TX
          </Button>
        </div>
      </Section>

      <ResultBox data={result} error={error} />
    </div>
  );
}

// ─── Label Sync section ─────────────────────────────────────────────────

function LabelSyncSection() {
  const [baseUrl, setBaseUrl] = useState('https://labels.example.com');
  const [walletId, setWalletId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string>('');

  const run = async (fn: () => Promise<any>, okMsg: string) => {
    setBusy(true);
    setError(null);
    setResult(null);
    setStatus('');
    try {
      const r = await fn();
      setResult(r ?? 'OK');
      setStatus(okMsg);
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <Section title="Label Sync Server">
        <div className="grid grid-cols-1 gap-3">
          <div>
            <Label text="Sync Server Base URL" />
            <Input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          </div>
          <div>
            <Label text="Wallet ID" />
            <Input value={walletId} onChange={(e) => setWalletId(e.target.value)} />
          </div>
          <div>
            <Label text="Passphrase" />
            <Input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
          </div>
          <div className="flex gap-2 flex-wrap">
            <Button
              onClick={() => run(() => api.labelSyncPush(baseUrl, walletId, passphrase, []), 'Pushed 0 labels (overwrite)')}
              disabled={busy || !walletId || !passphrase}
            >
              Push Labels
            </Button>
            <Button
              onClick={() => run(() => api.labelSyncPull(baseUrl, walletId, passphrase), `Pulled ${result?.length ?? 0} labels`)}
              disabled={busy || !walletId || !passphrase}
              variant="secondary"
            >
              Pull Labels
            </Button>
          </div>
          {status && <div className="text-xs text-success">{status}</div>}
        </div>
      </Section>

      <ResultBox data={result} error={error} />
    </div>
  );
}

// ─── Main view ──────────────────────────────────────────────────────────

export function ServicesView() {
  const [tab, setTab] = useState<ServiceTab>('spv');

  const tabs: { id: ServiceTab; label: string; icon: string }[] = [
    { id: 'spv', label: 'SPV Channels', icon: '📡' },
    { id: 'cosigner', label: 'Cosigner Pool', icon: '✍️' },
    { id: 'labelsync', label: 'Label Sync', icon: '🏷️' },
  ];

  return (
    <div className="p-4 h-full flex flex-col">
      <h2 className="text-lg font-semibold mb-3 text-accent">Network Services</h2>

      {/* Service tab bar */}
      <div className="flex gap-2 mb-4">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-3 py-1.5 rounded text-sm transition-colors ${
              tab === t.id
                ? 'bg-accent text-white'
                : 'bg-void-800 text-gray-400 hover:text-gray-200'
            }`}
          >
            <span className="mr-1.5">{t.icon}</span>
            {t.label}
          </button>
        ))}
      </div>

      {/* Active section */}
      <div className="flex-1 overflow-auto max-w-2xl">
        {tab === 'spv' && <SpvChannelsSection />}
        {tab === 'cosigner' && <CosignerPoolSection />}
        {tab === 'labelsync' && <LabelSyncSection />}
      </div>
    </div>
  );
}