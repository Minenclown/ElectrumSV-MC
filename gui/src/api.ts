// API client for ElectrumSV-Mc — Tauri IPC (no REST, no Python backend)
import { invoke } from '@tauri-apps/api/core';

// ─── Types matching Rust backend structs ───

/** NetworkDefinition matches Rust `commands::extra::NetworkDefinition` — static BSV network identity (mainnet / testnet / STN). */
export interface NetworkDefinition {
  id: string;
  name: string;
  default_ports: string[];
  bitcoin_uri_prefix: string;
}

/** NetworkInfo matches Rust `commands::network::NetworkInfo` — live connection status. */
export interface NetworkInfo {
  connected: boolean;
  backend_type: string | null;
  active_server: string | null;
  tip_height: number | null;
  server_count: number;
  connected_count: number;
  banned_count: number;
}

/** BalanceInfo matches Rust `commands::account::BalanceInfo` — wallet balance (i64 fields). */
export interface BalanceInfo {
  confirmed: number;
  unconfirmed: number;
  total: number;
}

/** UtxoEntry matches Rust `commands::account::UtxoEntry` — wallet UTXO from DB. */
export interface UtxoEntry {
  tx_hash: string;
  tx_index: number;
  value: number;
  keyinstance_id: number;
  is_coinbase: boolean;
}

/** HistoryEntry matches Rust `commands::account::HistoryEntry` — wallet transaction history. */
export interface HistoryEntry {
  tx_hash: string;
  value_delta: number;
  date_created: number;
  block_height: number | null;
  description: string | null;
}

/** AccountInfo matches Rust `commands::account::AccountInfo` — account summary. */
export interface AccountInfo {
  account_id: number;
  account_name: string;
  default_script_type: number;
}

/** PaymentOutput matches Rust `PaymentOutput { address, satoshis }` */
export interface PaymentOutput {
  address: string;
  satoshis: number;
}

/** DecodedOutput matches Rust `DecodedOutput` — classified on-chain data */
export interface DecodedOutput {
  output_index: number;
  value: number;
  script_pubkey_hex: string;
  kind: {
    type: 'ordinal' | 'op_return_protocol' | 'stas_token' | 'plain';
    // Ordinal fields
    protocol?: string;
    content_type?: string;
    content_hex?: string;
    content_text?: string | null;
    // OP_RETURN protocol fields
    data?: any;
    // STAS token fields
    symbol?: string | null;
    contract_txid?: string | null;
    amount?: number | null;
    script_hex?: string;
  };
}

/** TxPlan is deprecated — the backend no longer sends the full plan to the renderer.
 *  prepare_tx returns only a plan_id handle + metadata; the full plan stays server-side. */
// export interface TxPlan { ... }

/** ServerInfo matches Rust `commands::network::ServerEntry` — ElectrumX server list entry. */
export interface ServerInfo {
  host: string;
  s?: number;  // SSL port
  t?: number;  // TCP port
  note?: string;
}

export const api = {
  // App
  getAppVersion: () => invoke<string>('get_app_version'),

  // Wallet lifecycle
  createWallet: (password: string, walletName?: string, mnemonic?: string) =>
    invoke<any>('create_wallet', { name: walletName || 'default_wallet', password, mnemonic: mnemonic || null, passphrase: null }),
  openWallet: (walletPath: string) =>
    invoke<any>('open_wallet', { walletPath }),
  closeWallet: (walletPath: string) =>
    invoke<any>('close_wallet'),
  unlockWallet: (walletPath: string, password: string) =>
    invoke<any>('unlock_wallet', { password }),
  unlockWalletWithTOTP: (walletPath: string, password: string, _totpCode?: string) =>
    invoke<any>('unlock_wallet', { password }),
  listWallets: () => invoke<any[]>('list_wallets'),

  // Wallet info
  getWalletInfo: () => invoke<any>('get_wallet_status'),
  getAccounts: () => invoke<any[]>('get_accounts'),
  getBalance: (accountId?: number) =>
    invoke<BalanceInfo>('get_balance', { accountId: accountId ?? null }),
  getHistory: (accountId: number) =>
    invoke<any[]>('get_history', { accountId, limit: null, offset: null }),
  getUtxos: (accountId: number) =>
    invoke<any[]>('get_utxos', { accountId }),
  getKeys: (accountId: number) =>
    invoke<any[]>('get_keys', { accountId }),
  // Multisig account commands (Task 5)
  createMultisigAccount: (accountName: string, threshold: number, publicKeys: string[]) =>
    invoke<number>('create_multisig_account', { accountName, threshold, publicKeys }),
  getMultisigConfig: (accountId: number) =>
    invoke<{ account_id: number; threshold: number; num_keys: number; public_keys: string[] } | null>(
      'get_multisig_config', { accountId }
    ),
  getReceiveAddress: (accountId: number) =>
    // Backend returns { address, keyinstance_id, derivation_index }
    invoke<any>('get_receive_address', { accountId }).then(r => ({
      ...r,
      key_id: r?.keyinstance_id ?? null,
    })),
  getTransaction: (txid: string) =>
    invoke<{
      txid: string;
      status: string;
      raw_tx: string | null;
      account_id: number | null;
      fee: number | null;
      inputs: { prev_tx_hash: string; prev_vout: number; script_sig: string; sequence: number }[];
      outputs: { value: number; script_pubkey: string }[];
      label: string | null;
    }>('get_transaction', { txid }),

  // 3-stage transaction workflow
  // AUD-008: prepare_tx returns a plan_id handle + metadata only — the full
  // TxPlan stays server-side and is never sent to the renderer.
  prepareTx: (body: { outputs: PaymentOutput[]; feeRate: number; opReturn?: string }) =>
    invoke<{
      plan_id: string;
      fee: number;
      total_input: number;
      total_output: number;
      change: number;
      num_inputs: number;
      num_outputs: number;
    }>('prepare_tx', {
      outputs: body.outputs,
      feeRate: body.feeRate,
      opReturn: body.opReturn ?? null,
    }),

  // AUD-008: sign_tx takes a plan_id (server fetches the plan) + TOTP code
  signTx: (planId: string, totpCode: string) =>
    invoke<{ txid: string; signed_tx_hex: string }>('sign_tx', {
      planId,
      totpCode,
    }),

  // broadcast_tx: takes signed hex + expected txid (from sign_tx result)
  broadcastTx: (signedTxHex: string, expectedTxid: string) =>
    invoke<string>('broadcast_tx', { signedTxHex, expectedTxid }),

  // estimate_fee: returns { fee, num_inputs, num_outputs, fee_rate }
  estimateFee: (outputs: PaymentOutput[], feeRate: number, opReturn?: string) =>
    invoke<{ fee: number; num_inputs: number; num_outputs: number; fee_rate: number }>(
      'estimate_fee', { outputs, feeRate, opReturn: opReturn ?? null }
    ),

  // Network
  getNetworkInfo: () => invoke<NetworkInfo>('get_network_info'),
  getServers: () => invoke<ServerInfo[]>('get_servers'),
  connectServer: (host: string, port: number) =>
    invoke<any>('connect_server', { host, port }),
  disconnectServer: () =>
    invoke<any>('disconnect_server'),
  syncWallet: () =>
    invoke<any>('sync_wallet'),
  syncHeaders: () =>
    invoke<any>('sync_headers'),
  banServer: (host: string) =>
    invoke<any>('ban_server', { host }),
  setNetworkBackend: (backend: string) =>
    invoke<any>('set_network_backend', { backend }),
  getHeaderStoreInfo: () =>
    invoke<any>('get_header_store_info'),
  getServersByStatus: () =>
    invoke<any>('get_servers_by_status'),
  verifyTransactionProof: (txid: string, proof: string) =>
    invoke<any>('verify_transaction_proof', { txid, proof }),

  // Network switching
  listNetworks: () => invoke<NetworkDefinition[]>('list_networks'),
  switchNetwork: (networkId: string) =>
    invoke<string>('switch_network', { networkId }),

  // WhatsOnChain extras
  wocGetChainInfo: () =>
    invoke<any>('woc_get_chain_info'),
  wocGetBlockHeader: (height: number) =>
    invoke<any>('woc_get_block_header', { height }),
  wocGetTx: (txid: string) =>
    invoke<any>('woc_get_tx', { txid }),

  // Wallet utilities (extra)
  backupWallet: (backupPath: string) =>
    invoke<string>('backup_wallet', { backupPath }),
  importPrivkey: (wif: string, password: string) =>
    invoke<{ address: string; keyinstance_id: number }>('import_privkey', { wif, password }),
  send: (address: string, amount: number, password: string, totpCode: string, opReturn?: string, feeRate?: number) =>
    invoke<{ txid: string; status: string }>('send', {
      address, amount, password, totpCode,
      opReturn: opReturn ?? null, feeRate: feeRate ?? null,
    }),

  // TOTP scope management
  getTotpStatus: () =>
    invoke<{ enabled: boolean; scope: string; recovery_codes_remaining: number }>('get_totp_status'),
  setTotpScope: (password: string, scope: string, code?: string) =>
    invoke<string>('set_totp_scope', { password, scope, code: code ?? null }),

  // App name
  getAppName: () => invoke<string>('get_app_name'),

  // ─── BSV Ecosystem features ──────────────────────────────────────
  resolvePaymail: (handle: string) =>
    invoke<{ handle: string; address: string }>('resolve_paymail', { handle }),
  getExchangeRates: () =>
    invoke<{ currency: string; rate: number }[]>('get_exchange_rates'),
  getExchangeRate: (currency: string) =>
    invoke<number>('get_exchange_rate', { currency }),
  satoshisToFiat: (satoshis: number, currency: string) =>
    invoke<number>('satoshis_to_fiat', { satoshis, currency }),
  getMapiFeeQuote: (url?: string) =>
    invoke<{ mining_fee_satoshis: number; relay_fee_satoshis: number; raw: any }>('get_mapi_fee_quote', { url: url ?? null }),
  parseBip276Uri: (uri: string) =>
    invoke<{ valid: boolean; prefix: string | null; version: number | null; network: number | null; data_hex: string | null; error: string | null }>('parse_bip276_uri', { uri }),
  getCoinSelectionStrategies: () =>
    invoke<{ strategies: string[] }>('get_coin_selection_strategies'),

  // Config
  getConfig: () => invoke<any>('get_config'),
  updateConfig: (body: Record<string, any>) => {
    const entries = Object.entries(body);
    if (entries.length === 0) return Promise.resolve();
    const [key, value] = entries[0];
    return invoke<any>('update_config', { key, value: String(value) });
  },

  // Contacts — backend returns Vec<ContactInfo> (array, not { contacts: [...] })
  getContacts: () => invoke<any[]>('get_contacts'),
  addContact: (label: string, system: string, systemData: string) =>
    invoke<any>('add_contact', { label, system, systemData }),
  updateContact: (contactId: number, label: string) =>
    invoke<any>('update_contact', { contactId, label }),
  deleteContact: (contactId: number) =>
    invoke<any>('delete_contact', { contactId }),

  // Labels
  setKeyLabel: (keyId: number, label: string, _accountId: number) =>
    invoke<any>('set_key_label', { keyId, label }),
  setTxLabel: (txHash: string, label: string) =>
    invoke<any>('set_tx_label', { txHash, label }),

  // Payment Requests
  createPaymentRequest: (accountId: number, amount: number, label?: string) =>
    invoke<{ uri: string; address: string; amount: number; label: string | null; paymentrequest_id: number }>(
      'create_payment_request', { accountId, amount, label: label || null }
    ),
  listPaymentRequests: () => invoke<any[]>('list_payment_requests'),

  // Wallet utilities
  exportSeed: (password: string, totpCode?: string) =>
    invoke<any>('export_seed', { password, totpCode: totpCode ?? null }),
  exportPrivkey: (password: string, address?: string, all?: boolean, totpCode?: string) =>
    invoke<any>('export_privkey', { password, address: address || null, all: all || false, totpCode: totpCode ?? null }),
  changePassword: (oldPassword: string, newPassword: string) =>
    invoke<any>('change_password', { oldPassword, newPassword }),
  signMessage: (address: string, message: string, password: string) =>
    invoke<{ signature: string }>('sign_message', { address, message, password }),
  verifyMessage: (address: string, message: string, signature: string) =>
    invoke<{ valid: boolean }>('verify_message', { address, message, signature }),
  deleteWallet: (walletPath: string) =>
    invoke<any>('delete_wallet', { walletPath }),

  // TOTP — simplified model (one-step enable, no scope)
  // Backend: enable_totp() → { otpauth_url, secret_base32 }
  //          disable_totp() → ()
  //          verify_totp(code) → bool
  //          is_totp_enabled_cmd() → bool
  //          generate_totp_recovery_codes() → string[] (one-time display)
  //          totp_recover(recovery_code) → bool
  // NOTE: totpStatus() was removed — use getTotpStatus() instead.
  totpEnable: () =>
    invoke<{ otpauth_url: string; secret_base32: string }>('enable_totp'),
  totpDisable: () =>
    invoke<any>('disable_totp'),
  verifyTotp: (code: string) =>
    invoke<boolean>('verify_totp', { code }),
  generateTotpRecoveryCodes: () =>
    invoke<string[]>('generate_totp_recovery_codes'),
  totpRecover: (recoveryCode: string) =>
    invoke<boolean>('totp_recover', { recoveryCode }),

  // Hardware wallet
  setHardwareWalletEnabled: (enabled: boolean) =>
    invoke<any>('set_hardware_wallet_enabled', { enabled }),
  getHardwareWalletStatus: () =>
    invoke<boolean>('get_hardware_wallet_status'),

  // Session logout (no-op in Tauri — no server-side session)
  logout: () => Promise.resolve(),

  // Daemon log (no daemon in Tauri mode — return empty)
  getDaemonLog: (_lines?: number) =>
    Promise.resolve({ lines: [] }),

  // QR code generation — PicQr (Rust backend, replaces qrcode npm package)
  generateQr: (data: string, opts?: {
    ecLevel?: string;     // "L" | "M" | "Q" | "H"
    scale?: number;
    quietZone?: number;
    foreground?: string;  // hex "#000000"
    background?: string;  // hex "#FFFFFF"
    moduleShape?: string; // "square" | "rounded" | "dots"
  }) =>
    invoke<{ svg: string }>('generate_qr', {
      req: {
        data,
        ecLevel: opts?.ecLevel ?? null,
        scale: opts?.scale ?? null,
        quietZone: opts?.quietZone ?? null,
        foreground: opts?.foreground ?? null,
        background: opts?.background ?? null,
        moduleShape: opts?.moduleShape ?? null,
      },
    }),

  // ─── BSV on-chain data protocol decoding ───────────────────────────
  decodeOutput: (value: number, scriptPubkey: string) =>
    invoke<DecodedOutput>('decode_output', {
      req: { value, script_pubkey: scriptPubkey },
    }),

  decodeTxOutputs: (outputs: { value: number; script_pubkey: string }[]) =>
    invoke<DecodedOutput[]>('decode_tx_outputs', { req: { outputs } }),

  getOrdinals: (outputs: { value: number; script_pubkey: string }[]) =>
    invoke<DecodedOutput[]>('get_ordinals', { req: { outputs } }),

  getProtocolData: (outputs: { value: number; script_pubkey: string }[]) =>
    invoke<DecodedOutput[]>('get_protocol_data', { req: { outputs } }),

  getTokenTransfers: (outputs: { value: number; script_pubkey: string }[]) =>
    invoke<DecodedOutput[]>('get_token_transfers', { req: { outputs } }),

  // ─── SPV Channels ──────────────────────────────────────────────────
  /** SPV Channel as returned by the relay. */
  spvCreateChannel: (baseUrl: string, publicKey: string) =>
    invoke<{
      channel_id: string;
      public_key: string;
      description: string | null;
      active: boolean;
    }>('spv_create_channel', { baseUrl, publicKey: publicKey || null }),

  spvListMessages: (baseUrl: string, channelId: string) =>
    invoke<Array<{
      message_id: string;
      channel_id: string;
      encrypted_payload: string;
      received: number;
      read: boolean;
    }>>('spv_list_messages', { baseUrl, channelId }),

  spvPostMessage: (baseUrl: string, channelId: string, encryptedPayload: string) =>
    invoke<{
      message_id: string;
      channel_id: string;
      encrypted_payload: string;
      received: number;
      read: boolean;
    }>('spv_post_message', {
      baseUrl,
      channelId,
      message: { encrypted_payload: encryptedPayload },
    }),

  spvMarkRead: (baseUrl: string, channelId: string, messageId: string) =>
    invoke<void>('spv_mark_read', { baseUrl, channelId, messageId }),

  spvDeleteChannel: (baseUrl: string, channelId: string) =>
    invoke<void>('spv_delete_channel', { baseUrl, channelId }),

  // ─── Cosigner Pool ──────────────────────────────────────────────────
  cosignerSubmitTx: (
    baseUrl: string,
    tx: {
      wallet_id: string;
      txid: string;
      tx_hex: string;
      signers: string[];
      required_sigs: number;
      total_cosigners: number;
    },
  ) => invoke<void>('cosigner_submit_tx', { baseUrl, tx }),

  cosignerGetPending: (baseUrl: string, walletId: string) =>
    invoke<Array<{
      wallet_id: string;
      txid: string;
      tx_hex: string;
      signers: string[];
      required_sigs: number;
      total_cosigners: number;
    }>>('cosigner_get_pending', { baseUrl, walletId }),

  cosignerDeleteTx: (baseUrl: string, walletId: string, txid: string) =>
    invoke<void>('cosigner_delete_tx', { baseUrl, walletId, txid }),

  // ─── Label Sync ─────────────────────────────────────────────────────
  labelSyncPush: (
    baseUrl: string,
    walletId: string,
    passphrase: string,
    labels: Array<{ id: string; kind: 'address' | 'transaction'; label: string; updated_at: number }>,
  ) => invoke<void>('label_sync_push', { baseUrl, walletId, passphrase, labels }),

  labelSyncPull: (baseUrl: string, walletId: string, passphrase: string) =>
    invoke<Array<{
      id: string;
      kind: 'address' | 'transaction';
      label: string;
      updated_at: number;
    }>>('label_sync_pull', { baseUrl, walletId, passphrase }),
};