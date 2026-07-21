# ElectrumSV-Mc

A Bitcoin SV (BSV) desktop wallet built with **Rust** (Tauri v2) and **React** (TypeScript).

> **PROTOTYPE NOTICE:** This project is a prototype and has not undergone extensive real-world testing or production use. It is not recommended for storing or transacting significant amounts of BSV. Use at your own risk and always back up your keys.

---

## Features

### Wallet
- BIP39 mnemonic wallet creation (12/24 words)
- Wallet encryption (AES-CBC, password-derived)
- Multiple accounts per wallet
- Key import/export (WIF format)
- Wallet backup and delete (with path-traversal protection)
- Password change (re-encrypts xprv, mnemonic, passphrase)

### Transactions
- 3-stage send workflow: Prepare -> Sign -> Broadcast
- Server-side TxPlan binding (AUD-008): the renderer receives only a `plan_id` handle, never the unsigned transaction hex — preventing tampering
- Coin selection strategies: largest-first (default), branch-and-bound, random-subset, privacy
- mAPI fee estimation with fallback to 1 sat/byte
- OP_RETURN data output support
- BSM (Bitcoin Signed Message) signing and verification

### Security
- TOTP 2FA (login + transaction scope)
- TOTP required for seed export and private key export
- Recovery codes for TOTP bypass
- Path-traversal and symlink protection on wallet file operations
- Password verification on all sensitive operations

### On-Chain Data Detection
- **Controller+Handle Pattern**: `DetectorController` (OnceLock singleton) with 3 handles:
  - Ordinal detector (1Sat Ordinals NFT envelope parsing)
  - OP_RETURN protocol decoder (B, MAP, Bcat, BAP, 21E8)
  - STAS token transfer detector

### BSV Ecosystem
- PayMail address resolution (handle -> BSV address)
- Exchange rate lookup (multi-provider, fiat display)
- mAPI (Merchant API) fee quotes and transaction submission
- BIP276 `bitcoin-script://` URI parser with checksum validation
- SPV Channels (encrypted P2P messaging)
- Cosigner Pool (multi-sig transaction coordination)
- Label Sync (wallet label synchronization across devices)

### Network
- ElectrumX protocol support (server connection, header sync, UTXO/history queries)
- WhatsOnChain REST API integration (chain info, block headers, transactions)
- Network switching (mainnet, testnet, STN)
- Server list management with ban/penalty system

### GUI (12 tabs)
- Send, Receive (with BIP276 URI parser + QR codes), History
- Network (connect/disconnect/sync/switch), Security (TOTP scope management)
- Ordinals (NFT browser), Tokens (STAS + OP_RETURN browser)
- Services (SPV/Cosigner/LabelSync), Contacts, Payment Requests, Labels, Settings

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Rust 2021 edition, Tauri v2 |
| Frontend | React 18, TypeScript, Zustand, TailwindCSS |
| Build | Vite 5, cargo |
| Database | SQLite (sqlx async) |
| Crypto | bsv-sdk (Rust), sha2, aes, hmac |
| QR Codes | PicQr (custom Rust crate, no external QR libs) |

---

## Architecture

```
commands/        Tauri IPC commands (89 registered)
  -> services/   Wallet service layer
  -> core/       Transaction builder, signer, keystore, coinchooser, multisig
  -> features/   On-chain detection (Controller+Handle), ecosystem modules
  -> network/    ElectrumX, WhatsOnChain, server list, header store
  -> db/         SQLite repositories, migration system, transaction cache
  -> security/   TOTP, encryption, BSM
  -> state/      AppState (active wallet, network, pending plans)
```

### Tauri Commands: 89
- 54 wallet/account/network/transaction commands
- 5 feature commands (decode outputs, ordinals, protocol data, token transfers)
- 11 extra commands (TOTP scope, send, backup, import, WoC)
- 6 ecosystem commands (PayMail, exchange rate, mAPI, BIP276, coin selection)
- 10 service commands (SPV Channels, Cosigner Pool, Label Sync)
- 2 multisig commands
- 1 QR code command

---

## Testing

| Suite | Count | Status |
|-------|-------|--------|
| Rust unit tests | 512 | all passing |
| Integration tests | 3 | all passing |
| E2E lifecycle test | 1 | passing |
| GUI (vitest) | 14 | all passing |
| **Total** | **530** | |

```bash
# Run all tests
cd src-tauri && cargo test          # Rust tests (516)
cd gui && npx tsc --noEmit          # TypeScript check (0 errors)
cd gui && npx vitest run            # GUI tests (14)
```

---

## Getting Started

### Prerequisites
- Rust (stable, 2021 edition)
- Node.js 18+ and npm
- Tauri CLI v2 (`cargo install tauri-cli --version "^2.0"`)

### Development

```bash
# Clone and run
git clone <repo-url>
cd electrumsv-mc
./start.sh

# Or manually:
cd gui && npm install
cd src-tauri && cargo tauri dev
```

### Build

```bash
cd src-tauri && cargo tauri build
```

---

## License

This project includes code derived from Electrum, ElectrumSV, and Electron Cash.

Portions of this software were previously distributed under the MIT License, and some components may also be distributed under the Open BSV License. Original license notices are preserved.

See `LICENCE` for details.

---

## Acknowledgements

- [ElectrumSV](https://github.com/electrumsv/electrumsv) — original Python wallet
- [bsv-sdk](https://github.com/bsv-blockchain-programming/bsv-sdk) — BSV toolkit for Rust
- [Tauri](https://tauri.app/) — desktop application framework
- [PicQr](https://github.com/Minenclown/picqr) — QR code generation (Rust crate)