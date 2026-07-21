# Contributing to ElectrumSV-Mc

## Development Setup

```bash
git clone git@github.com:Minenclown/ElectrumSV-MC.git
cd ElectrumSV-MC
./start.sh
```

### Prerequisites
- Rust (stable, 2021 edition)
- Node.js 18+ and npm
- Tauri CLI v2

## Code Style

- **Rust**: Follow `cargo fmt` and `cargo clippy` — zero warnings
- **TypeScript/React**: Follow existing patterns in `gui/src/`
- **Commits**: English-only, conventional commit messages

## Testing

All tests must pass before a PR can be merged:

```bash
cd src-tauri && cargo test           # 519 lib + 6 E2E/integration
cd gui && npx vitest run              # 14 GUI tests
```

When adding features, add tests. When fixing bugs, add a regression test.

## Architecture

The project uses a **Controller+Handle** architecture:
- `commands/` — Tauri IPC (90 registered commands)
- `services/` — wallet service layer
- `core/` — transaction builder, signer, keystore
- `features/` — on-chain detection, ecosystem modules
- `network/` — ElectrumX, WhatsOnChain

See `README.md` for the full architecture overview.

## QR Code Backend

QR codes use a build-time feature flag (Murena-Prinzip):
- Default: PicQr (standalone, no external QR libs)
- Fallback: `qrcode` crate (`--features qrcode-fallback`)

Both backends enforce ISO/IEC 18004 quiet zone minimum (4 modules).

## License

By contributing, you agree that your contributions will be dual-licensed under
the Open BSV License and the MIT License. See [LICENSE](LICENSE).