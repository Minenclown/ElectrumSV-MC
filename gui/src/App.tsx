// Main App — ElectrumSV-Mc GUI
// ElectrumSV-Original-Layout: MenuBar (top) → TabBar → Content (with left sidebar) → StatusBar (bottom)
// View routing: landing → login → main, Quit returns to landing

import { useEffect, useState } from 'react';
import { useStore } from './store';
import { api } from './api';
import { MenuBar } from './components/MenuBar';
import { StatusBar } from './components/StatusBar';
import { LandingPage } from './views/LandingPage';
import { LoginScreen } from './views/LoginScreen';
import { HistoryView } from './views/HistoryView';
import { SendView } from './views/SendView';
import { ReceiveView } from './views/ReceiveView';
import { ContactsView } from './views/ContactsView';
import { UtxoView } from './views/UtxoView';
import { SecurityView } from './views/SecurityView';
import { NetworkView } from './views/NetworkView';
import { ConsoleView } from './views/ConsoleView';
import { OrdinalsView } from './views/OrdinalsView';
import { TokensView } from './views/TokensView';
import { ServicesView } from './views/ServicesView';
// useDaemonLifecycle removed — Tauri mode has no daemon

function getTabs(t: ReturnType<typeof useTranslation>['t']) {
  return [
    { id: 'history', label: t.tabs.history, icon: '📋' },
    { id: 'send', label: t.tabs.send, icon: '📤' },
    { id: 'receive', label: t.tabs.receive, icon: '📥' },
    { id: 'contacts', label: t.tabs.contacts, icon: '👥' },
    { id: 'utxos', label: t.tabs.utxos, icon: '💰' },
    { id: 'ordinals', label: t.tabs.ordinals, icon: '🖼' },
    { id: 'tokens', label: t.tabs.tokens, icon: '🪙' },
    { id: 'services', label: t.tabs.services, icon: '🔧' },
    { id: 'security', label: t.tabs.security, icon: '🔒' },
    { id: 'network', label: t.tabs.network, icon: '🌐' },
    { id: 'console', label: t.tabs.console, icon: '🖥' },
  ];
}

import { useTranslation } from './i18n';

function AccountSidebar() {
  const { walletName, balances, activeAccountId, accounts, setActiveAccount } = useStore();
  const { t } = useTranslation();
  const totalBalance = Object.values(balances).reduce<number>((a, b) => a + (b.total || 0), 0);
  const confirmedBalance = Object.values(balances).reduce<number>((a, b) => a + (b.confirmed || 0), 0);
  const unconfirmedBalance = Object.values(balances).reduce<number>((a, b) => a + (b.unconfirmed || 0), 0);
  const [fiatTotal, setFiatTotal] = useState<number | null>(null);
  const [fiatCurrency, setFiatCurrency] = useState('USD');

  // Fetch exchange rate and show fiat equivalent
  useEffect(() => {
    if (totalBalance === 0) { setFiatTotal(null); return; }
    api.satoshisToFiat(totalBalance, fiatCurrency)
      .then(setFiatTotal)
      .catch(() => setFiatTotal(null));
  }, [totalBalance, fiatCurrency]);

  return (
    <div className="w-56 bg-void-900 h-full flex flex-col border-r border-void-700 overflow-y-auto">
      {/* Wallet name */}
      <div className="p-3 border-b border-void-700">
        <div className="text-sm font-semibold text-accent truncate">{walletName || t.sidebar.noWallet}</div>
        <div className="text-xs text-gray-400 mt-1">{t.sidebar.account} #{activeAccountId ?? '-'}</div>
      </div>

      {/* Balance summary */}
      <div className="p-3 border-b border-void-700">
        <div className="text-xs text-gray-400 mb-1">{t.sidebar.totalBalance}</div>
        <div className="text-lg font-semibold text-yellow-400">{totalBalance.toLocaleString()} sat</div>
        {fiatTotal !== null && (
          <div className="text-xs text-gray-400 mt-0.5">
            ≈ {fiatTotal.toFixed(2)} {fiatCurrency}
          </div>
        )}
        <div className="mt-2 space-y-1">
          <div className="flex justify-between text-xs">
            <span className="text-gray-400">{t.sidebar.confirmed}</span>
            <span className="text-success">{confirmedBalance.toLocaleString()}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="text-gray-400">{t.sidebar.unconfirmed}</span>
            <span className="text-warning">{unconfirmedBalance.toLocaleString()}</span>
          </div>
        </div>
      </div>

      {/* Account list */}
      <div className="p-3 border-b border-void-700">
        <div className="text-xs text-gray-400 mb-2">{t.sidebar.accounts}</div>
        {accounts.map((acc) => {
          const isActive = acc.id === activeAccountId;
          const bal = balances[String(acc.id)];
          return (
            <button
              key={acc.id}
              onClick={() => setActiveAccount(acc.id)}
              className={`w-full text-left py-1.5 px-2 rounded text-sm transition-colors ${
                isActive
                  ? 'bg-void-800 text-accent border-l-2 border-accent'
                  : 'text-gray-300 hover:bg-void-800 border-l-2 border-transparent'
              }`}
            >
              <div className="flex justify-between items-center">
                <span>#{acc.id} {acc.name || acc.type}</span>
                {bal && (
                  <span className="text-xs text-gray-400">{bal.total.toLocaleString()}</span>
                )}
              </div>
            </button>
          );
        })}
      </div>

      {/* Spacer */}
      <div className="flex-1 p-3">
        <div className="text-xs text-gray-400 mb-2">{t.sidebar.activeTab}</div>
      </div>
    </div>
  );
}

function MainView() {
  const {
    activeTab, setActiveTab,
    setNetworkInfo, setWalletInfo, setAccounts, setActiveAccount,
    updateBalance, activeAccountId, isAuthenticated, setError,
    triggerHistoryRefresh,
  } = useStore();
  const { t } = useTranslation();
  const TABS = getTabs(t);

  // Load data on mount
  useEffect(() => {
    if (!isAuthenticated) return;

    api.getNetworkInfo()
      .then((info: any) => {
        setNetworkInfo({
          connected: info.connected ?? false,
          network: useStore.getState().network,
          blockHeight: info.tip_height ?? 0,
        });
      })
      .catch((e: Error) => setError(`Network info: ${e.message}`));

    api.getWalletInfo()
      .then((r: any) => {
        setWalletInfo({ walletName: r.wallet_name ?? '', walletLoaded: true });
      })
      .catch((e: Error) => setError(`Wallet info: ${e.message}`));

    api.getAccounts()
      .then((accounts: any) => {
        const accountList = Array.isArray(accounts) ? accounts : (accounts.accounts ?? []);
        const mapped = accountList.map((a: any) => ({
          id: a.account_id ?? a.id,
          name: a.account_name ?? a.name ?? '',
          type: 'standard',
        }));
        setAccounts(mapped);
        if (mapped.length > 0 && mapped[0].id !== undefined) {
          setActiveAccount(mapped[0].id);
          for (const acc of mapped) {
            api.getBalance(acc.id)
              .then((bal: any) => {
                updateBalance(String(acc.id), {
                  confirmed: bal.confirmed ?? 0,
                  unconfirmed: bal.unconfirmed ?? 0,
                  unmatured: 0,
                  total: bal.total ?? 0,
                });
              })
              .catch((e: Error) => setError(`Balance for account ${acc.id}: ${e.message}`));
          }
        }
      })
      .catch((e: Error) => setError(`Accounts: ${e.message}`));
  }, [isAuthenticated]);

  // Tauri Events: Live updates (replaces SSE/EventSource)
  useEffect(() => {
    if (!isAuthenticated) return;

    let cancelled = false;
    let unlistenFns: (() => void)[] = [];

    (async () => {
      const { listen } = await import('@tauri-apps/api/event');
      if (cancelled) return;

      const unlisten1 = await listen('new_transaction', (event) => {
        const data = event.payload as any;
        triggerHistoryRefresh();
        if (data.account_id !== undefined) {
          api.getBalance(data.account_id)
            .then((bal: any) => {
              updateBalance(String(data.account_id), {
                confirmed: bal.confirmed ?? 0,
                unconfirmed: bal.unconfirmed ?? 0,
                unmatured: 0,
                total: bal.total ?? 0,
              });
            })
            .catch(() => {});
        }
      });

      const unlisten2 = await listen('balance_changed', (event) => {
        const data = event.payload as any;
        if (data.account_id !== undefined) {
          updateBalance(String(data.account_id), {
            confirmed: data.confirmed ?? 0,
            unconfirmed: data.unconfirmed ?? 0,
            unmatured: 0,
            total: data.total ?? 0,
          });
        }
      });

      const unlisten3 = await listen('new_block', (event) => {
        const data = event.payload as any;
        setNetworkInfo({
          connected: true,
          network: useStore.getState().network,
          blockHeight: data.height ?? 0,
        });
      });

      unlistenFns = [unlisten1, unlisten2, unlisten3];
    })().catch(() => {
      // Tauri event listener setup failed — non-fatal
    });

    return () => {
      cancelled = true;
      unlistenFns.forEach((fn) => fn());
    };
  }, [isAuthenticated]);

  // Refresh balance on account switch
  useEffect(() => {
    if (!isAuthenticated || activeAccountId === null) return;
    api.getBalance(activeAccountId)
      .then((bal: any) => {
        updateBalance(String(activeAccountId), {
          confirmed: bal.confirmed ?? 0,
          unconfirmed: bal.unconfirmed ?? 0,
          unmatured: bal.unmatured ?? 0,
          total: bal.total ?? 0,
        });
      })
      .catch((e: Error) => setError(`Balance refresh: ${e.message}`));
  }, [activeAccountId, isAuthenticated, setError]);

  const handleQuit = async () => {
    // Close the active wallet before returning to landing
    const { activeWalletPath, resetToLanding } = useStore.getState();
    if (activeWalletPath) {
      try {
        await api.closeWallet(activeWalletPath);
      } catch {
        // Wallet might already be closed — ignore
      }
    }
    resetToLanding();
  };

  return (
    <div className="flex flex-col h-screen bg-void-950 text-gray-100">
      {/* Menu bar (top) */}
      <MenuBar onQuit={handleQuit} />

      {/* Tab bar (horizontal tabs like ElectrumSV) */}
      <div className="flex bg-void-900 border-b border-void-700">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 text-sm flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-accent text-accent bg-void-800'
                : 'border-transparent text-gray-400 hover:text-gray-100 hover:bg-void-800'
            }`}
          >
            <span>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main content area: sidebar + view */}
      <div className="flex flex-1 overflow-hidden">
        <AccountSidebar />
        <main className="flex-1 overflow-auto">
          {activeTab === 'history' && <HistoryView />}
          {activeTab === 'send' && <SendView />}
          {activeTab === 'receive' && <ReceiveView />}
          {activeTab === 'contacts' && <ContactsView />}
          {activeTab === 'utxos' && <UtxoView />}
          {activeTab === 'ordinals' && <OrdinalsView />}
          {activeTab === 'tokens' && <TokensView />}
          {activeTab === 'services' && <ServicesView />}
          {activeTab === 'security' && <SecurityView />}
          {activeTab === 'network' && <NetworkView />}
          {activeTab === 'console' && <ConsoleView />}
        </main>
      </div>

      {/* Status bar (bottom) */}
      <StatusBar />
    </div>
  );
}

function App() {
  const { view, isAuthenticated } = useStore();
  // useDaemonLifecycle removed — Tauri mode has no daemon

  if (view === 'landing') return <LandingPage />;
  if (view === 'login' || !isAuthenticated) return <LoginScreen />;
  return <MainView />;
}

export default App;