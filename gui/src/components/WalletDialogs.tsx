// Wallet dialog components — Export Seed, Change Password, Sign/Verify Message, Delete Wallet
import { useState } from 'react';
import { api } from '../api';
import { useStore } from '../store';
import { Modal, Field, inputClass, btnPrimary, btnSecondary } from './Modal';

// ─── Export Seed Dialog ───
export function ExportSeedDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { setError } = useStore();
  const [password, setPassword] = useState('');
  const [mnemonic, setMnemonic] = useState<string | null>(null);
  const [hasSeed, setHasSeed] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  const handleExport = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.exportSeed(password);
      setHasSeed(r.has_seed);
      setMnemonic(r.mnemonic);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    setPassword('');
    setMnemonic(null);
    setHasSeed(null);
    onClose();
  };

  return (
    <Modal title="Export Seed" open={open} onClose={handleClose}>
      {!mnemonic && (
        <>
          <p className="text-sm text-gray-400 mb-3">
            Enter your wallet password to reveal your BIP39 mnemonic seed.
          </p>
          <Field label="Wallet password">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className={inputClass} placeholder="••••••••" />
          </Field>
          <div className="flex gap-3">
            <button onClick={handleExport} disabled={busy || !password} className={btnPrimary}>
              {busy ? 'Exporting…' : 'Reveal Seed'}
            </button>
            <button onClick={handleClose} className={btnSecondary}>Cancel</button>
          </div>
        </>
      )}
      {mnemonic && hasSeed && (
        <>
          <p className="text-sm text-warning mb-3">
            ⚠ Write down these words and keep them safe. Never share them with anyone.
          </p>
          <div className="bg-void-950 border border-void-700 rounded-lg p-3 mb-3">
            <p className="font-mono text-sm text-gray-100 leading-relaxed">{mnemonic}</p>
          </div>
          <button onClick={handleClose} className={btnPrimary}>Done</button>
        </>
      )}
      {hasSeed === false && (
        <>
          <p className="text-sm text-gray-400 mb-3">This wallet has no seed (watch-only or imported keys).</p>
          <button onClick={handleClose} className={btnPrimary}>OK</button>
        </>
      )}
    </Modal>
  );
}

// ─── Change Password Dialog ───
export function ChangePasswordDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { setError } = useStore();
  const [oldPwd, setOldPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [busy, setBusy] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleChange = async () => {
    if (newPwd !== confirmPwd) {
      setError('New passwords do not match');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.changePassword(oldPwd, newPwd);
      setSuccess(true);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    setOldPwd(''); setNewPwd(''); setConfirmPwd(''); setSuccess(false);
    onClose();
  };

  return (
    <Modal title="Change Password" open={open} onClose={handleClose}>
      {!success ? (
        <>
          <Field label="Current password">
            <input type="password" value={oldPwd} onChange={(e) => setOldPwd(e.target.value)}
              className={inputClass} placeholder="••••••••" />
          </Field>
          <Field label="New password">
            <input type="password" value={newPwd} onChange={(e) => setNewPwd(e.target.value)}
              className={inputClass} placeholder="••••••••" />
          </Field>
          <Field label="Confirm new password">
            <input type="password" value={confirmPwd} onChange={(e) => setConfirmPwd(e.target.value)}
              className={inputClass} placeholder="••••••••" />
          </Field>
          <div className="flex gap-3">
            <button onClick={handleChange} disabled={busy || !oldPwd || !newPwd || !confirmPwd} className={btnPrimary}>
              {busy ? 'Changing…' : 'Change Password'}
            </button>
            <button onClick={handleClose} className={btnSecondary}>Cancel</button>
          </div>
        </>
      ) : (
        <>
          <p className="text-sm text-success mb-3">✓ Password changed successfully.</p>
          <button onClick={handleClose} className={btnPrimary}>OK</button>
        </>
      )}
    </Modal>
  );
}

// ─── Sign Message Dialog ───
export function SignMessageDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { setError, activeAccountId } = useStore();
  const [address, setAddress] = useState('');
  const [message, setMessage] = useState('');
  const [password, setPassword] = useState('');
  const [signature, setSignature] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const handleSign = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.signMessage(address, message, password);
      setSignature(r.signature);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    setAddress(''); setMessage(''); setPassword(''); setSignature(null);
    onClose();
  };

  return (
    <Modal title="Sign Message" open={open} onClose={handleClose}>
      {!signature ? (
        <>
          <Field label="Address">
            <input type="text" value={address} onChange={(e) => setAddress(e.target.value)}
              className={inputClass} placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" />
          </Field>
          <Field label="Message">
            <textarea value={message} onChange={(e) => setMessage(e.target.value)}
              className={inputClass} rows={3} placeholder="Enter message to sign" />
          </Field>
          <Field label="Wallet password">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className={inputClass} placeholder="••••••••" />
          </Field>
          <div className="flex gap-3">
            <button onClick={handleSign} disabled={busy || !address || !message || !password} className={btnPrimary}>
              {busy ? 'Signing…' : 'Sign'}
            </button>
            <button onClick={handleClose} className={btnSecondary}>Cancel</button>
          </div>
        </>
      ) : (
        <>
          <Field label="Signature">
            <div className="bg-void-950 border border-void-700 rounded-lg p-3">
              <p className="font-mono text-sm text-gray-100 break-all">{signature}</p>
            </div>
          </Field>
          <button onClick={() => navigator.clipboard.writeText(signature)} className={btnSecondary + ' mr-2'}>Copy</button>
          <button onClick={handleClose} className={btnPrimary}>Done</button>
        </>
      )}
    </Modal>
  );
}

// ─── Verify Message Dialog ───
export function VerifyMessageDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { setError } = useStore();
  const [address, setAddress] = useState('');
  const [message, setMessage] = useState('');
  const [signature, setSignature] = useState('');
  const [result, setResult] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  const handleVerify = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.verifyMessage(address, message, signature);
      setResult(r.valid);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    setAddress(''); setMessage(''); setSignature(''); setResult(null);
    onClose();
  };

  return (
    <Modal title="Verify Message" open={open} onClose={handleClose}>
      <Field label="Address">
        <input type="text" value={address} onChange={(e) => setAddress(e.target.value)}
          className={inputClass} placeholder="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" />
      </Field>
      <Field label="Message">
        <textarea value={message} onChange={(e) => setMessage(e.target.value)}
          className={inputClass} rows={3} placeholder="Message" />
      </Field>
      <Field label="Signature">
        <textarea value={signature} onChange={(e) => setSignature(e.target.value)}
          className={inputClass} rows={2} placeholder="base64 signature" />
      </Field>
      {result !== null && (
        <div className={`text-sm mb-3 font-medium ${result ? 'text-success' : 'text-error'}`}>
          {result ? '✓ Signature is valid' : '✗ Signature is invalid'}
        </div>
      )}
      <div className="flex gap-3">
        <button onClick={handleVerify} disabled={busy || !address || !message || !signature} className={btnPrimary}>
          {busy ? 'Verifying…' : 'Verify'}
        </button>
        <button onClick={handleClose} className={btnSecondary}>Cancel</button>
      </div>
    </Modal>
  );
}

// ─── Delete Wallet Dialog ───
export function DeleteWalletDialog({ open, onClose, walletPath, walletName, onDeleted }: {
  open: boolean;
  onClose: () => void;
  walletPath: string;
  walletName: string;
  onDeleted: () => void;
}) {
  const { setError } = useStore();
  const [confirmName, setConfirmName] = useState('');
  const [busy, setBusy] = useState(false);

  const handleDelete = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.deleteWallet(walletPath);
      onDeleted();
      onClose();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    setConfirmName('');
    onClose();
  };

  return (
    <Modal title="Delete Wallet" open={open} onClose={handleClose}>
      <p className="text-sm text-error mb-3">
        ⚠ This will permanently delete the wallet file. This action cannot be undone.
      </p>
      <p className="text-sm text-gray-400 mb-3">
        Type the wallet name <span className="text-gray-100 font-mono">{walletName}</span> to confirm:
      </p>
      <Field label="Confirm wallet name">
        <input type="text" value={confirmName} onChange={(e) => setConfirmName(e.target.value)}
          className={inputClass} placeholder={walletName} />
      </Field>
      <div className="flex gap-3">
        <button onClick={handleDelete} disabled={busy || confirmName !== walletName}
          className="bg-error hover:bg-red-700 text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
          {busy ? 'Deleting…' : 'Delete Permanently'}
        </button>
        <button onClick={handleClose} className={btnSecondary}>Cancel</button>
      </div>
    </Modal>
  );
}

// ─── Backup Wallet Dialog ───
export function BackupWalletDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { setError } = useStore();
  const [backupPath, setBackupPath] = useState('');
  const [busy, setBusy] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);

  const handleBackup = async () => {
    setBusy(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await api.backupWallet(backupPath);
      setSuccess(`Wallet backed up to: ${result}`);
    } catch (e: any) {
      setError(e.message || 'Backup failed');
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    setBackupPath('');
    setSuccess(null);
    onClose();
  };

  return (
    <Modal title="Backup Wallet" open={open} onClose={handleClose}>
      <p className="text-sm text-gray-400 mb-3">
        Create a backup copy of your wallet database file.
      </p>
      <Field label="Backup file path">
        <input type="text" value={backupPath} onChange={(e) => setBackupPath(e.target.value)}
          className={inputClass} placeholder="/path/to/wallet_backup.sqlite" />
      </Field>
      {success && (
        <div className="text-sm text-success mb-3 p-3 bg-success/10 rounded-lg">{success}</div>
      )}
      <div className="flex gap-3">
        <button onClick={handleBackup} disabled={busy || !backupPath} className={btnPrimary}>
          {busy ? 'Backing up…' : 'Backup'}
        </button>
        <button onClick={handleClose} className={btnSecondary}>Close</button>
      </div>
    </Modal>
  );
}

// ─── Import Private Key Dialog ───
export function ImportPrivkeyDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { walletPassword, setError } = useStore();
  const [wif, setWif] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ address: string; keyinstance_id: number } | null>(null);

  const handleImport = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.importPrivkey(wif, password || walletPassword || '');
      setResult(r);
    } catch (e: any) {
      setError(e.message || 'Import failed');
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    setWif('');
    setPassword('');
    setResult(null);
    onClose();
  };

  return (
    <Modal title="Import Private Key" open={open} onClose={handleClose}>
      {!result && (
        <>
          <p className="text-sm text-gray-400 mb-3">
            Import a private key in WIF (Wallet Import Format) to add it as an imported key.
          </p>
          <Field label="WIF private key">
            <input type="text" value={wif} onChange={(e) => setWif(e.target.value)}
              className={inputClass} placeholder="L..." />
          </Field>
          <Field label="Wallet password">
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className={inputClass} placeholder={walletPassword ? '(stored password)' : '••••••••'} />
          </Field>
          <div className="flex gap-3">
            <button onClick={handleImport} disabled={busy || !wif} className={btnPrimary}>
              {busy ? 'Importing…' : 'Import Key'}
            </button>
            <button onClick={handleClose} className={btnSecondary}>Cancel</button>
          </div>
        </>
      )}
      {result && (
        <>
          <p className="text-sm text-success mb-3">
            ✓ Private key imported successfully!
          </p>
          <div className="bg-void-950 border border-void-700 rounded-lg p-3 mb-3">
            <div className="text-xs text-gray-400 mb-1">Address:</div>
            <div className="text-sm font-mono text-gray-100">{result.address}</div>
            <div className="text-xs text-gray-400 mt-2 mb-1">Key ID:</div>
            <div className="text-sm font-mono text-gray-100">{result.keyinstance_id}</div>
          </div>
          <button onClick={handleClose} className={btnPrimary}>Done</button>
        </>
      )}
    </Modal>
  );
}