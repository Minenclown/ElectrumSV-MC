// network/networks.rs — BSV network definitions
//
// Ported from archive/electrumsv/networks.py and networks_mainnet.py.
// Defines four BSV networks: mainnet, testnet, scaling testnet, and regtest.
// Each network carries address types, port configs, genesis hashes, URI prefixes,
// server lists, checkpoints, block explorers, and more.
//
// This module does NOT modify any existing files. It is standalone and will
// be wired into the module tree by the caller in a later milestone.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ElectrumX error code for block height out of range.
pub const BLOCK_HEIGHT_OUT_OF_RANGE_ERROR: i32 = -8;

// ---------------------------------------------------------------------------
// Default ports
// ---------------------------------------------------------------------------

/// Default ElectrumX ports for mainnet: TCP 50001, SSL 50002.
pub const MAINNET_PORTS: Ports = Ports { tcp: 50001, ssl: 50002 };
/// Default ElectrumX ports for testnet/scaling testnet: TCP 51001, SSL 51002.
pub const TESTNET_PORTS: Ports = Ports { tcp: 51001, ssl: 51002 };

/// A pair of default ports for an ElectrumX server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ports {
    /// TCP (plaintext) port.
    pub tcp: u16,
    /// SSL/TLS port.
    pub ssl: u16,
}

// ---------------------------------------------------------------------------
// Checkpoint
// ---------------------------------------------------------------------------

/// A post-split checkpoint: a block header hash and height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Raw header bytes (hex-encoded in the Python source).
    pub raw_header_hex: String,
    /// Block height of the checkpoint.
    pub height: u64,
    /// Previous accumulated work (hex string from Python `prev_work`).
    pub prev_work_hex: String,
}

// ---------------------------------------------------------------------------
// Block explorer
// ---------------------------------------------------------------------------

/// A block explorer entry: (name, base_url, path mapping).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockExplorer {
    /// Display name (e.g. "whatsonchain.com").
    pub name: String,
    /// Base URL (e.g. "https://whatsonchain.com").
    pub base_url: String,
    /// Path suffixes for tx/addr/script lookups.
    pub tx_path: String,
    pub addr_path: String,
    /// Script path is optional (some explorers lack it).
    pub script_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Network enum / NetworkDef
// ---------------------------------------------------------------------------

/// The BSV network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet,
    ScalingTestnet,
    Regtest,
}

impl NetworkType {
    /// String name matching the Python `NAME` field.
    pub fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::ScalingTestnet => "scalingtestnet",
            Self::Regtest => "regtest",
        }
    }

    /// Parse from a string (case-insensitive).
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mainnet" => Some(Self::Mainnet),
            "testnet" => Some(Self::Testnet),
            "scalingtestnet" => Some(Self::ScalingTestnet),
            "regtest" => Some(Self::Regtest),
            _ => None,
        }
    }
}

/// Full definition of a BSV network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDef {
    /// Network type identifier.
    pub net_type: NetworkType,
    /// P2PKH address version byte.
    pub addrtype_p2pkh: u8,
    /// P2SH address version byte.
    pub addrtype_p2sh: u8,
    /// CashAddr prefix (legacy field from BCH, retained for compatibility).
    pub cashaddr_prefix: &'static str,
    /// Default ElectrumX ports.
    pub default_ports: Ports,
    /// Genesis block hash (hex, big-endian display).
    pub genesis_hash: &'static str,
    /// Bitcoin URI prefix (e.g. "bitcoin:").
    pub bitcoin_uri_prefix: &'static str,
    /// Pay URI prefix (e.g. "pay:").
    pub pay_uri_prefix: &'static str,
    /// WIF private key prefix byte.
    pub wif_prefix: u8,
    /// BIP276 version number.
    pub bip276_version: u32,
    /// Bitcoin Cash fork block height (legacy, retained for compatibility).
    pub bitcoin_cash_fork_block_height: u64,
    /// Bitcoin Cash fork block hash (legacy).
    pub bitcoin_cash_fork_block_hash: &'static str,
    /// BIP44 coin type.
    pub bip44_coin_type: u32,
    /// Faucet URL for testnet/regtest.
    pub faucet_url: &'static str,
    /// Whether the 20-minute rule applies (testnet only).
    pub twenty_minute_rule: bool,
    /// KeepKey display coin name.
    pub keepkey_display_coin_name: &'static str,
    /// Trezor coin name.
    pub trezor_coin_name: &'static str,
    /// Checkpoint (may be `None` for regtest).
    pub checkpoint: Option<Checkpoint>,
    /// Verification block merkle root (may be `None` for regtest/scaling testnet).
    pub verification_block_merkle_root: Option<&'static str>,
    /// Block explorers.
    pub block_explorers: Vec<BlockExplorer>,
    /// Known ElectrumX server hosts (from servers.json, simplified to host:ssl_port).
    pub default_servers: Vec<ServerHost>,
}

/// A server hostname + port entry (simplified from the Python server dicts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHost {
    /// Hostname (e.g. "electrumx.gorillapool.io").
    pub host: &'static str,
    /// SSL port.
    pub ssl_port: u16,
}

// ---------------------------------------------------------------------------
// Mainnet
// ---------------------------------------------------------------------------

/// Mainnet network definition.
pub fn mainnet() -> NetworkDef {
    NetworkDef {
        net_type: NetworkType::Mainnet,
        addrtype_p2pkh: 0,
        addrtype_p2sh: 5,
        cashaddr_prefix: "bitcoincash",
        default_ports: MAINNET_PORTS,
        genesis_hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        bitcoin_uri_prefix: "bitcoin",
        pay_uri_prefix: "pay",
        wif_prefix: 0x80,
        bip276_version: 1,
        bitcoin_cash_fork_block_height: 478559,
        bitcoin_cash_fork_block_hash:
            "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec",
        bip44_coin_type: 0,
        faucet_url: "https://faucet.satoshisvision.network",
        twenty_minute_rule: false,
        keepkey_display_coin_name: "Bitcoin",
        trezor_coin_name: "Bcash",
        checkpoint: Some(Checkpoint {
            raw_header_hex: "0000003662b03d134146d61e3ae43875760491a9e2022a3df73662190000000000000000b3a89c221e127ad51f0abee5442762c72f46aa7855591d6a37ba1af426ad4513bc814e6a595527183bda0b3e".to_string(),
            height: 957000,
            prev_work_hex: "16d70fa39ef1576eaf44c06".to_string(),
        }),
        verification_block_merkle_root: Some(
            "916212962437fa0f6473e3a452b1f1cbfdd392ba2d48c1e5132e7ccc5b13fb45",
        ),
        block_explorers: vec![
            BlockExplorer {
                name: "satoshi.io".into(),
                base_url: "https://satoshi.io".into(),
                tx_path: "tx".into(),
                addr_path: "address".into(),
                script_path: Some("script".into()),
            },
            BlockExplorer {
                name: "whatsonchain.com".into(),
                base_url: "https://whatsonchain.com".into(),
                tx_path: "tx".into(),
                addr_path: "address".into(),
                script_path: Some("script".into()),
            },
            BlockExplorer {
                name: "bitails.io".into(),
                base_url: "https://bitails.io".into(),
                tx_path: "tx".into(),
                addr_path: "address".into(),
                script_path: Some("script".into()),
            },
        ],
        default_servers: mainnet_servers(),
    }
}

/// Known mainnet ElectrumX servers (from servers.json, subset of the Python default).
fn mainnet_servers() -> Vec<ServerHost> {
    vec![
        ServerHost { host: "electrumx-bsv.theprivate.family", ssl_port: 50002 },
        ServerHost { host: "electrum.api.sv", ssl_port: 50002 },
        ServerHost { host: "sv.torypolicy.com", ssl_port: 50002 },
    ]
}

// ---------------------------------------------------------------------------
// Testnet
// ---------------------------------------------------------------------------

/// Testnet network definition.
pub fn testnet() -> NetworkDef {
    NetworkDef {
        net_type: NetworkType::Testnet,
        addrtype_p2pkh: 111,
        addrtype_p2sh: 196,
        cashaddr_prefix: "bchtest",
        default_ports: TESTNET_PORTS,
        genesis_hash: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        bitcoin_uri_prefix: "bitcoin",
        pay_uri_prefix: "pay",
        wif_prefix: 0xef,
        bip276_version: 2,
        bitcoin_cash_fork_block_height: 1155876,
        bitcoin_cash_fork_block_hash:
            "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5e",
        bip44_coin_type: 1,
        faucet_url: "https://testnet.satoshisvision.network",
        twenty_minute_rule: true,
        keepkey_display_coin_name: "Testnet",
        trezor_coin_name: "Bcash Testnet",
        checkpoint: Some(Checkpoint {
            raw_header_hex: "00000020f248a5cf335bb0964833cb81bae10b2f47cc640f477d44926d000000000000005e737849ae351b1d17e0fc3e9032ffd889ad218d561143a883a3664a4e20e0729bc1b3634485021a68ca47cc".to_string(),
            height: 1530084,
            prev_work_hex: "1346dab3d7c7e35b984".to_string(),
        }),
        verification_block_merkle_root: Some(
            "2ee768ac67da75c6df3326bd5d680ff39faeec07174e1d500fa0b6ca35932112",
        ),
        block_explorers: vec![
            BlockExplorer {
                name: "whatsonchain.com".into(),
                base_url: "http://test.whatsonchain.com".into(),
                tx_path: "tx".into(),
                addr_path: "address".into(),
                script_path: Some("script".into()),
            },
            BlockExplorer {
                name: "satoshi.io".into(),
                base_url: "https://testnet.satoshi.io".into(),
                tx_path: "tx".into(),
                addr_path: "address".into(),
                script_path: Some("script".into()),
            },
        ],
        default_servers: vec![
            ServerHost { host: "electrumx-testnet.theprivate.family", ssl_port: 51002 },
        ],
    }
}

// ---------------------------------------------------------------------------
// Scaling Testnet
// ---------------------------------------------------------------------------

/// Scaling Testnet network definition.
pub fn scaling_testnet() -> NetworkDef {
    NetworkDef {
        net_type: NetworkType::ScalingTestnet,
        addrtype_p2pkh: 111,
        addrtype_p2sh: 196,
        cashaddr_prefix: "bchtest",
        default_ports: TESTNET_PORTS,
        genesis_hash: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        bitcoin_uri_prefix: "bitcoin",
        pay_uri_prefix: "pay",
        wif_prefix: 0xef,
        bip276_version: 3,
        bitcoin_cash_fork_block_height: 0,
        bitcoin_cash_fork_block_hash: "",
        bip44_coin_type: 1,
        faucet_url: "https://faucet.bitcoinscaling.io",
        twenty_minute_rule: true,
        keepkey_display_coin_name: "Testnet",
        trezor_coin_name: "Bcash Testnet",
        checkpoint: Some(Checkpoint {
            raw_header_hex: "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18".to_string(),
            height: 0,
            prev_work_hex: "0".to_string(),
        }),
        verification_block_merkle_root: None,
        block_explorers: vec![
            BlockExplorer {
                name: "bitails.io".into(),
                base_url: "https://bitails.io".into(),
                tx_path: "tx".into(),
                addr_path: "address".into(),
                script_path: None,
            },
            BlockExplorer {
                name: "whatsonchain.com".into(),
                base_url: "http://stn.whatsonchain.com".into(),
                tx_path: "tx".into(),
                addr_path: "address".into(),
                script_path: None,
            },
            BlockExplorer {
                name: "satoshi.io".into(),
                base_url: "https://stn.satoshi.io".into(),
                tx_path: "tx".into(),
                addr_path: "address".into(),
                script_path: None,
            },
        ],
        default_servers: vec![
            ServerHost { host: "electrumx-stn.theprivate.family", ssl_port: 51002 },
        ],
    }
}

// ---------------------------------------------------------------------------
// Regtest
// ---------------------------------------------------------------------------

/// Regtest network definition (commented out in Python, included here for completeness).
pub fn regtest() -> NetworkDef {
    NetworkDef {
        net_type: NetworkType::Regtest,
        addrtype_p2pkh: 111,
        addrtype_p2sh: 196,
        cashaddr_prefix: "bchtest",
        default_ports: TESTNET_PORTS,
        genesis_hash: "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        bitcoin_uri_prefix: "bitcoin",
        pay_uri_prefix: "pay",
        wif_prefix: 0xef,
        bip276_version: 2,
        bitcoin_cash_fork_block_height: 0,
        bitcoin_cash_fork_block_hash: "",
        bip44_coin_type: 1,
        faucet_url: "",
        twenty_minute_rule: true,
        keepkey_display_coin_name: "Testnet",
        trezor_coin_name: "Bcash Testnet",
        checkpoint: Some(Checkpoint {
            raw_header_hex: "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18".to_string(),
            height: 0,
            prev_work_hex: "0".to_string(),
        }),
        verification_block_merkle_root: None,
        block_explorers: vec![],
        default_servers: vec![ServerHost { host: "localhost", ssl_port: 51002 }],
    }
}

// ---------------------------------------------------------------------------
// Registry — get a network by type
// ---------------------------------------------------------------------------

/// Get the `NetworkDef` for the given `NetworkType`.
pub fn get_network(net: NetworkType) -> NetworkDef {
    match net {
        NetworkType::Mainnet => mainnet(),
        NetworkType::Testnet => testnet(),
        NetworkType::ScalingTestnet => scaling_testnet(),
        NetworkType::Regtest => regtest(),
    }
}

/// Get all four network definitions.
pub fn all_networks() -> Vec<NetworkDef> {
    vec![
        mainnet(),
        testnet(),
        scaling_testnet(),
        regtest(),
    ]
}

// ---------------------------------------------------------------------------
// URI construction
// ---------------------------------------------------------------------------

impl NetworkDef {
    /// Build a "bitcoin:" BIP21 URI for a payment.
    pub fn bitcoin_uri(&self, address: &str, amount_sats: u64) -> String {
        format!(
            "{}:{}?amount={}",
            self.bitcoin_uri_prefix,
            address,
            amount_sats as f64 / 1e8
        )
    }

    /// Build a "pay:" URI (BSV pay-to-endpoint style).
    pub fn pay_uri(&self, endpoint: &str) -> String {
        format!("{}:{}", self.pay_uri_prefix, endpoint)
    }

    /// Get the block explorer URL for a transaction.
    pub fn explorer_tx_url(&self, explorer_idx: usize, txid: &str) -> Option<String> {
        self.block_explorers.get(explorer_idx).map(|e| {
            format!("{}/{}/{}", e.base_url, e.tx_path, txid)
        })
    }

    /// Get the block explorer URL for an address.
    pub fn explorer_addr_url(&self, explorer_idx: usize, address: &str) -> Option<String> {
        self.block_explorers.get(explorer_idx).map(|e| {
            format!("{}/{}/{}", e.base_url, e.addr_path, address)
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_definition() {
        let net = mainnet();
        assert_eq!(net.net_type, NetworkType::Mainnet);
        assert_eq!(net.addrtype_p2pkh, 0);
        assert_eq!(net.addrtype_p2sh, 5);
        assert_eq!(net.default_ports.tcp, 50001);
        assert_eq!(net.default_ports.ssl, 50002);
        assert_eq!(net.wif_prefix, 0x80);
        assert_eq!(net.bip276_version, 1);
        assert_eq!(net.bip44_coin_type, 0);
        assert!(!net.twenty_minute_rule);
        assert!(net.checkpoint.is_some());
        let cp = net.checkpoint.as_ref().unwrap();
        assert_eq!(cp.height, 957000);
    }

    #[test]
    fn test_testnet_definition() {
        let net = testnet();
        assert_eq!(net.net_type, NetworkType::Testnet);
        assert_eq!(net.addrtype_p2pkh, 111);
        assert_eq!(net.addrtype_p2sh, 196);
        assert_eq!(net.default_ports.tcp, 51001);
        assert_eq!(net.wif_prefix, 0xef);
        assert_eq!(net.bip44_coin_type, 1);
        assert!(net.twenty_minute_rule);
        assert!(net.checkpoint.is_some());
    }

    #[test]
    fn test_scaling_testnet_definition() {
        let net = scaling_testnet();
        assert_eq!(net.net_type, NetworkType::ScalingTestnet);
        assert_eq!(net.bip276_version, 3);
        assert_eq!(net.faucet_url, "https://faucet.bitcoinscaling.io");
        assert!(net.twenty_minute_rule);
        assert!(net.verification_block_merkle_root.is_none());
    }

    #[test]
    fn test_regtest_definition() {
        let net = regtest();
        assert_eq!(net.net_type, NetworkType::Regtest);
        assert_eq!(net.default_ports.tcp, 51001);
        assert!(net.default_servers.iter().any(|s| s.host == "localhost"));
    }

    #[test]
    fn test_network_type_name_roundtrip() {
        for nt in [
            NetworkType::Mainnet,
            NetworkType::Testnet,
            NetworkType::ScalingTestnet,
            NetworkType::Regtest,
        ] {
            let name = nt.name();
            assert_eq!(NetworkType::from_name(name), Some(nt));
        }
    }

    #[test]
    fn test_get_network_dispatch() {
        assert_eq!(get_network(NetworkType::Mainnet).addrtype_p2pkh, 0);
        assert_eq!(get_network(NetworkType::Testnet).addrtype_p2pkh, 111);
    }

    #[test]
    fn test_all_networks_count() {
        let nets = all_networks();
        assert_eq!(nets.len(), 4);
    }

    #[test]
    fn test_bitcoin_uri() {
        let net = mainnet();
        let uri = net.bitcoin_uri("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 50000);
        assert!(uri.starts_with("bitcoin:1A1zP1eP5"));
        assert!(uri.contains("amount="));
    }

    #[test]
    fn test_explorer_urls() {
        let net = mainnet();
        let tx_url = net.explorer_tx_url(0, "deadbeef").unwrap();
        assert!(tx_url.contains("deadbeef"));
        let addr_url = net.explorer_addr_url(1, "1A1zP1eP5").unwrap();
        assert!(addr_url.contains("1A1zP1eP5"));
    }

    #[test]
    fn test_genesis_hashes() {
        let mn = mainnet();
        assert_eq!(
            mn.genesis_hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        let tn = testnet();
        assert_eq!(
            tn.genesis_hash,
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        );
    }
}