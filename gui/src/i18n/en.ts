// i18n/en.ts — English translations
// All UI strings keyed by namespace.section.key

export const en = {
  // Landing page
  landing: {
    title: 'ElectrumSV-Mc',
    subtitle: 'Bitcoin SV Wallet',
    apiConnected: 'API connected',
    apiWaiting: 'Waiting for API…',
    token: 'token',
    hide: 'hide',
    apiTokenLabel: 'API Token (auto-generated, local only)',
    yourWallets: 'Your Wallets',
    noWallets: 'No wallets found.',
    open: 'Open',
    createNew: '+ Create New Wallet',
    footer: 'ElectrumSV-Mc — Standalone BSV Wallet',
    language: 'Language',
  },

  // Login screen
  login: {
    title: 'ElectrumSV-Mc',
    subtitle: 'Bitcoin SV Wallet',
    sessionActive: '2FA session active',
    apiTokenReady: 'API token ready',
    noToken: 'No API token — go back',
    unlockWallet: 'Unlock Wallet',
    newWallet: 'New Wallet',
    unlockSelected: 'Enter your wallet password.',
    enterNamePassword: 'Enter wallet name and password to open.',
    walletName: 'Wallet name',
    walletPassword: 'Wallet password',
    totpRequired: '🔒 This wallet has 2FA enabled. Enter the 6-digit code from your authenticator app.',
    totpPlaceholder: '6-digit TOTP code',
    unlock2fa: 'Unlock with 2FA',
    unlocking: 'Unlocking…',
    createDesc: 'Create a new BIP32 wallet with a BIP39 mnemonic seed. You\'ll get a 12-word seed phrase to back up.',
    walletNamePlaceholder: 'Wallet name (e.g. my_wallet)',
    newPassword: 'New wallet password',
    creating: 'Creating…',
    createWallet: 'Create Wallet',
    backToWallets: '← Back to wallet list',
    // Mnemonic steps
    backupSeed: 'Backup Your Seed',
    backupWarning: '⚠ Write down these {count} words and keep them safe. Without this seed, you cannot recover your wallet if you lose your password.',
    yourMnemonic: 'Your Mnemonic Seed',
    mnemonicNext: 'In the next step, you\'ll be asked to type these words to confirm your backup.',
    writtenDown: 'I\'ve written it down →',
    skipConfirm: 'Skip confirmation (not recommended)',
    confirmSeed: 'Confirm Your Seed',
    confirmDesc: 'Type your seed words below to confirm you\'ve backed them up correctly.',
    confirmPlaceholder: 'Enter your seed words here…',
    confirmOpen: 'Confirm & Open Wallet',
    backToSeed: '← Back to seed',
    mnemonicMismatch: 'Mnemonic does not match. Please write down your seed words exactly as shown.',
    loginFailed: 'Login failed',
    createFailed: 'Wallet creation failed',
    loadFailed: 'Failed to load wallet info',
  },

  // Main view — tabs
  tabs: {
    history: 'History',
    send: 'Send',
    receive: 'Receive',
    contacts: 'Contacts',
    utxos: 'UTXOs',
    ordinals: 'Ordinals',
    tokens: 'Tokens',
    services: 'Services',
    security: 'Security',
    network: 'Network',
    console: 'Console',
  },

  // Sidebar
  sidebar: {
    noWallet: 'No wallet',
    account: 'Account',
    totalBalance: 'Total Balance',
    confirmed: 'Confirmed',
    unconfirmed: 'Unconfirmed',
    accounts: 'Accounts',
    activeTab: 'Active Tab',
  },

  // Menu bar
  menu: {
    file: 'File',
    newWallet: 'New Wallet…',
    openWallet: 'Open Wallet…',
    closeWallet: 'Close Wallet',
    quit: 'Quit',
    wallet: 'Wallet',
    deleteWallet: 'Delete Wallet',
    changePassword: 'Change Password…',
    exportSeed: 'Export Seed…',
    tools: 'Tools',
    signMessage: 'Sign Message…',
    verifyMessage: 'Verify Message…',
    help: 'Help',
    about: 'About ElectrumSV-Mc',
    documentation: 'Documentation',
    language: 'Language',
    english: 'English',
    german: 'Deutsch',
  },

  // Status bar
  status: {
    connected: 'Connected',
    disconnected: 'Disconnected',
    block: 'Block',
  },

  // Send view
  send: {
    title: 'Send',
    address: 'Recipient address',
    amount: 'Amount (satoshis)',
    opReturn: 'OP_RETURN data (optional)',
    feeRate: 'Fee rate (sat/byte)',
    estimateFee: 'Estimate Fee',
    prepare: 'Prepare Transaction',
    preview: 'Transaction Preview',
    fee: 'Fee',
    change: 'Change',
    total: 'Total',
    signBroadcast: 'Sign & Broadcast',
    broadcasting: 'Broadcasting…',
    newTransaction: 'New Transaction',
    txid: 'Transaction ID',
    sendAnother: 'Send Another',
    preparing: 'Preparing…',
    selectContact: 'Select contact',
  },

  // Receive view
  receive: {
    title: 'Receive',
    address: 'Address',
    label: 'Label',
    showQR: 'Show QR',
    hideQR: 'Hide QR',
    paymentRequest: 'Payment Request',
    amount: 'Amount (satoshis)',
    createRequest: 'Create Request',
    requests: 'Payment Requests',
    noAddresses: 'No addresses available.',
    loading: 'Loading addresses…',
  },

  // History view
  history: {
    title: 'History',
    noTransactions: 'No transactions yet.',
    loading: 'Loading history…',
    confirmed: 'Confirmed',
    unconfirmed: 'Unconfirmed',
    txid: 'TXID',
    status: 'Status',
    fee: 'Fee',
    inputs: 'Inputs',
    outputs: 'Outputs',
  },

  // Contacts view
  contacts: {
    title: 'Contacts',
    add: 'Add Contact',
    label: 'Label',
    address: 'BSV address',
    addBtn: 'Add',
    delete: 'Delete',
    edit: 'Edit',
    noContacts: 'No contacts yet.',
    loading: 'Loading contacts…',
  },

  // UTXO view
  utxos: {
    title: 'UTXOs',
    loading: 'Loading UTXOs…',
    noUtxos: 'No UTXOs available.',
    address: 'Address',
    value: 'Value',
    status: 'Status',
  },

  // Security view
  security: {
    title: 'Security',
    passwordOnly: 'Password only (no 2FA)',
    totpLogin: 'Password + TOTP at login',
    totpTx: 'Password + TOTP at login + transactions',
    enable2fa: 'Enable 2FA',
    disable2fa: 'Disable 2FA',
    setupTotp: 'Setup TOTP',
    scanQr: 'Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)',
    enterCode: 'Enter the 6-digit code from your app to verify',
    verify: 'Verify & Enable',
    recoveryCodes: 'Recovery Codes',
    recoveryWarning: 'Save these recovery codes in a safe place. You will need them if you lose your authenticator device.',
    recoveryRemaining: 'Recovery codes remaining: {count}/10',
    lostDevice: 'Lost device? Use recovery code →',
    recover: 'Recover',
    recoveryCode: 'Recovery code',
    recoverBtn: 'Disable 2FA with recovery code',
    scopeLogin: 'Require TOTP at login',
    scopeTx: 'Also require TOTP for transactions',
  },

  // Network view
  network: {
    title: 'Network',
    status: 'Status',
    blockHeight: 'Block height',
    server: 'Server',
    servers: 'Servers',
    connected: 'Connected',
    disconnected: 'Disconnected',
  },

  // Console view
  console: {
    title: 'Console',
    loading: 'Loading daemon log…',
    noLog: 'No log output yet.',
    authFailed: 'Failed to fetch daemon log (auth required).',
    autoScroll: 'Auto-scroll',
  },

  // Common
  common: {
    loading: 'Loading…',
    error: 'Error',
    cancel: 'Cancel',
    close: 'Close',
    ok: 'OK',
    save: 'Save',
    delete: 'Delete',
    confirm: 'Confirm',
    back: '← Back',
  },
};

export type Translations = typeof en;