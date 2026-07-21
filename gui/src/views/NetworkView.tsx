// Network view — network status, server list, connect/disconnect, sync, network switching
import { useEffect, useState, useCallback } from 'react';
import { api } from '../api';

export function NetworkView() {
  const [info, setInfo] = useState<any>(null);
  const [servers, setServers] = useState<Record<string, any>>({});
  const [networks, setNetworks] = useState<{ id: string; name: string }[]>([]);
  const [activeNetwork, setActiveNetwork] = useState('mainnet');
  const [headerStore, setHeaderStore] = useState<any>(null);
  const [chainInfo, setChainInfo] = useState<any>(null);
  const [connecting, setConnecting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [netInfo, srvResult, netList, hdrStore] = await Promise.all([
        api.getNetworkInfo().catch(() => null),
        api.getServers().catch(() => null),
        api.listNetworks().catch(() => []),
        api.getHeaderStoreInfo().catch(() => null),
      ]);
      if (netInfo) setInfo(netInfo);
      if (srvResult) setServers((srvResult as any).servers || {});
      if (netList) setNetworks(netList as any[]);
      if (hdrStore) setHeaderStore(hdrStore);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleConnect = async (host: string) => {
    setConnecting(true);
    setError(null);
    setSuccess(null);
    try {
      const serverInfo = servers[host];
      const port = serverInfo?.s || serverInfo?.t || 50001;
      await api.connectServer(host, port);
      setSuccess(`Connected to ${host}`);
      await loadData();
    } catch (e: any) {
      setError(e.message || `Failed to connect to ${host}`);
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    setConnecting(true);
    setError(null);
    try {
      await api.disconnectServer();
      setSuccess('Disconnected');
      await loadData();
    } catch (e: any) {
      setError(e.message || 'Disconnect failed');
    } finally {
      setConnecting(false);
    }
  };

  const handleSyncWallet = async () => {
    setSyncing(true);
    setError(null);
    try {
      await api.syncWallet();
      setSuccess('Wallet synced');
    } catch (e: any) {
      setError(e.message || 'Sync failed');
    } finally {
      setSyncing(false);
    }
  };

  const handleSyncHeaders = async () => {
    setSyncing(true);
    setError(null);
    try {
      await api.syncHeaders();
      setSuccess('Headers synced');
      await loadData();
    } catch (e: any) {
      setError(e.message || 'Header sync failed');
    } finally {
      setSyncing(false);
    }
  };

  const handleBanServer = async (host: string) => {
    setError(null);
    try {
      await api.banServer(host);
      setSuccess(`Banned ${host}`);
      await loadData();
    } catch (e: any) {
      setError(e.message || `Failed to ban ${host}`);
    }
  };

  const handleSwitchNetwork = async (networkId: string) => {
    setError(null);
    try {
      await api.switchNetwork(networkId);
      setActiveNetwork(networkId);
      setSuccess(`Switched to ${networkId}`);
      await loadData();
    } catch (e: any) {
      setError(e.message || `Failed to switch to ${networkId}`);
    }
  };

  const handleFetchChainInfo = async () => {
    setError(null);
    try {
      const info = await api.wocGetChainInfo();
      setChainInfo(info);
    } catch (e: any) {
      setError(e.message || 'Failed to fetch chain info');
    }
  };

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold mb-4 text-accent">Network</h2>
      <div className="space-y-4 max-w-2xl">
        {/* Status + actions */}
        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">Status</div>
          <div className="flex items-center gap-2 mb-3">
            <span className={`w-2 h-2 rounded-full ${info?.connected ? 'bg-success' : 'bg-danger'}`} />
            <span className="text-sm text-gray-100">
              {info?.connected ? 'Connected' : 'Disconnected'} — {activeNetwork}
            </span>
          </div>
          {info && (
            <div className="text-sm text-gray-400 mt-1">
              Tip: block {info.tip_height ?? 0}
            </div>
          )}
          {headerStore && (
            <div className="text-xs text-gray-500 mt-1">
              Headers: {headerStore.count ?? '?'} | Best height: {headerStore.best_height ?? '?'}
            </div>
          )}
          <div className="flex gap-2 mt-3">
            <button
              onClick={handleSyncWallet}
              disabled={syncing}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-3 py-1.5 text-xs font-medium disabled:opacity-50 transition-colors"
            >
              {syncing ? 'Syncing…' : 'Sync Wallet'}
            </button>
            <button
              onClick={handleSyncHeaders}
              disabled={syncing}
              className="bg-void-800 hover:bg-void-700 text-gray-100 rounded-lg px-3 py-1.5 text-xs font-medium border border-void-700 disabled:opacity-50 transition-colors"
            >
              Sync Headers
            </button>
            {info?.connected && (
              <button
                onClick={handleDisconnect}
                disabled={connecting}
                className="text-danger hover:text-red-400 rounded-lg px-3 py-1.5 text-xs font-medium border border-danger/30 transition-colors"
              >
                {connecting ? '…' : 'Disconnect'}
              </button>
            )}
          </div>
        </div>

        {/* Network switching */}
        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">Network</div>
          <div className="flex gap-2">
            {networks.map((net) => (
              <button
                key={net.id}
                onClick={() => handleSwitchNetwork(net.id)}
                className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                  activeNetwork === net.id
                    ? 'bg-accent text-white border-accent'
                    : 'bg-void-800 text-gray-300 border-void-700 hover:border-accent'
                }`}
              >
                {net.name}
              </button>
            ))}
            {networks.length === 0 && (
              <span className="text-xs text-gray-400">Loading networks…</span>
            )}
          </div>
        </div>

        {/* Server list */}
        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">ElectrumX Servers</div>
          <div className="space-y-1">
            {Object.entries(servers).map(([host, srvInfo]: [string, any]) => (
              <div key={host} className="text-sm text-gray-300 font-mono flex items-center justify-between">
                <span>{host} <span className="text-gray-400">: {srvInfo.s || srvInfo.t}</span></span>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleConnect(host)}
                    disabled={connecting}
                    className="text-xs text-accent hover:text-accent-hover disabled:opacity-50"
                  >
                    Connect
                  </button>
                  <button
                    onClick={() => handleBanServer(host)}
                    className="text-xs text-danger hover:text-red-400"
                  >
                    Ban
                  </button>
                </div>
              </div>
            ))}
            {!Object.keys(servers).length && <div className="text-gray-400">No servers loaded.</div>}
          </div>
        </div>

        {/* WhatsOnChain chain info */}
        <div className="bg-void-900 rounded-lg p-4">
          <div className="text-sm text-gray-400 mb-2">WhatsOnChain</div>
          <button
            onClick={handleFetchChainInfo}
            className="bg-void-800 hover:bg-void-700 text-gray-100 rounded-lg px-3 py-1.5 text-xs font-medium border border-void-700 transition-colors"
          >
            Fetch Chain Info
          </button>
          {chainInfo && (
            <pre className="mt-2 text-xs text-gray-400 font-mono overflow-x-auto">
              {JSON.stringify(chainInfo, null, 2)}
            </pre>
          )}
        </div>

        {error && <div className="text-sm text-danger p-3 bg-danger/10 rounded-lg">{error}</div>}
        {success && <div className="text-sm text-success p-3 bg-success/10 rounded-lg">{success}</div>}
      </div>
    </div>
  );
}