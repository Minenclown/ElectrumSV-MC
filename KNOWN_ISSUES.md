# Known Issues

> Last updated: 2026-07-23 (v0.1.1)
> This is a **prototype** — see [PROTOTYPE NOTICE](README.md) in README.

## Security

### TOTP secret stored unencrypted
The TOTP secret is stored as plaintext in the wallet SQLite database despite the column name suggesting encryption. Anyone with file-level access to the wallet `.sqlite` file can extract the TOTP secret and bypass 2FA.

### No Content Security Policy (CSP)
The Tauri webview has no CSP configured (`csp: null`). This means the wallet UI has no protection against XSS attacks. If a dependency is compromised or user input is rendered without escaping, arbitrary JavaScript could execute with full access to Tauri IPC commands.

### `delete_wallet` does not require password
The `delete_wallet` command does not verify the wallet password before permanently deleting the wallet file. A compromised renderer process can destroy a wallet without knowing the password.

### `backup_wallet` does not require password
The `backup_wallet` command copies the wallet database file without password verification. A compromised renderer can exfiltrate the encrypted wallet database for offline brute-force attacks.

### `open_wallet` lacks path confinement
Unlike `delete_wallet` and `backup_wallet`, the `open_wallet` command does not validate that the provided path is within the application data directory. An arbitrary SQLite file could be loaded as a wallet.

### TOTP enable/disable without password verification
The `enable_totp` and `disable_totp` commands do not verify the wallet password. A compromised renderer can disable 2FA or replace the TOTP secret with one it controls.

### `sign_message` bypasses TOTP
Signing a message with a private key does not require TOTP verification, even when TOTP is enabled for transaction signing. This allows producing cryptographic proofs of address ownership without 2FA.

### `shell:allow-open` capability is overly broad
The Tauri capabilities include `shell:allow-open` without domain restrictions. Combined with the missing CSP, this increases the attack surface for XSS-driven attacks.

## Functional

### Network view: server port always wrong
The TypeScript `ServerInfo` interface uses field names `s` and `t` for SSL/TCP ports, but the Rust backend returns `ssl_port` and `tcp_port`. The network view always falls back to port 50001 and cannot connect to the correct port.

### Network view: server list always empty
The frontend expects the server list as a dictionary object, but the backend returns an array. The server list in the network view is always empty.

### UTXO view always shows "No unspent outputs"
The UTXO view expects a wrapped object (`r.utxos`) but the backend returns a bare array. UTXOs are never displayed even when they exist.

### History view: all transactions show as "Pending"
The history view accesses `tx.height` and `tx.status` but the Rust `HistoryEntry` struct uses `block_height`. Every transaction displays as "Pending" with no date, even confirmed ones.

### UTXO view: vout column shows undefined
The UTXO view accesses `u.vout` but the Rust struct field is `tx_index`. The vout column is always undefined.

### Multisig signing not registered
The `sign_multisig_tx` command is defined in the backend but not registered in the Tauri `generate_handler!` macro. Multisig transaction signing from the GUI returns "command not found".

### `sweep_legacy_to_new` bypasses secure signing pipeline
The legacy sweep command signs and broadcasts directly without going through the `prepare_tx` -> `sign_tx` -> `broadcast_tx` pipeline. This means no TOTP verification and no local txid validation before broadcast.

### Imported private keys are not spendable
The `import_privkey` command stores encrypted WIF keys, but the `LocalSigner` only supports BIP32-derived keys. Funds sent to imported key addresses cannot be spent with the current implementation.

### `switch_network` does not disconnect active backend
Switching networks updates the active network ID but does not disconnect the current ElectrumX or WoC client. The wallet could sync against the wrong network's servers.

### Services view "Sign Locally" is a placeholder
The "Sign Locally" button in the services view uses the transaction txid as a placeholder plan_id and passes an empty TOTP code. It always fails.

### Console view is a static placeholder
The console view shows a hardcoded static message. No backend logs are displayed.

### Backup and import dialogs never rendered
`BackupWalletDialog` and `ImportPrivkeyDialog` components exist in the codebase but are never rendered in the UI. These features are invisible to users.

## Robustness

### Mutex panics can crash the backend
Over 50 production code paths use `.lock().unwrap()`. If any thread panics while holding a Mutex, all subsequent lock attempts will panic, crashing the wallet backend. Combined with `panic = "abort"` in release builds, any panic terminates the process immediately.

### `unreachable!()` in sweep command
The `sweep_legacy_to_new` command uses `unreachable!()` for a backend-not-connected case. If the logic is ever refactored, this becomes a live crash.

### Fee iteration loop has no iteration cap
The fee convergence loop in `TxBuilder::build_unsigned` has no maximum iteration count. In theory it could oscillate, though in practice it converges because fees are monotonically increasing with more inputs.

### Decrypted xprv held in memory indefinitely
After unlocking, the decrypted xprv is stored as a plaintext `String` in memory for the entire session. There is no auto-lock timeout and no zeroization on drop.

### Empty password bypasses encryption
The encryption module silently degrades to no encryption when an empty password is used. While wallet creation validates non-empty passwords, `unlock_wallet` does not explicitly reject empty passwords.

## i18n

### Many hardcoded English strings
The i18n system exists with complete English/German key parity, but most views bypass it and use hardcoded English strings. German users see a mix of English and German in the UI.

## Build

### Linux-only build targets
Only `.deb`, `.rpm`, and `.AppImage` targets are configured. macOS and Windows users must build from source.

### picqr Git dependency without version pin
The `picqr` crate is included via Git URL without a pinned commit hash. Build reproducibility depends on the GitHub repository remaining available and unchanged.