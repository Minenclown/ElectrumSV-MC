// network/mod.rs — Network layer: ElectrumX + WhatsOnChain backends (Milestone 4)
//
// This module provides the network abstraction for communicating with BSV
// blockchain servers. It defines a common trait (`NetworkBackend`) that both
// ElectrumX (TCP+TLS, JSON-RPC) and WhatsOnChain (REST API) implement.
//
// AUDIT REQUIREMENTS (must be enforced in all implementations):
// - AUD-006: broadcast_tx must return a validated txid, never None.
// - AUD-Fund #6: Full TLS certificate + hostname verification, no permissive
//   verifier. Server responses must be cryptographically validated.
// - AUD-007: TOTP protection is not bypassable (enforced at command layer).

pub mod backend;
pub mod electrumx;
pub mod header_store;
pub mod networks;
pub mod server_list;
pub mod whatsonchain;

// Re-export key types for convenience.
pub use backend::{
    BackendType, BackendBalance, BlockHeader, BroadcastResult, MerkleProof, NetworkBackend,
    NetworkError, TxHistoryEntry, UtxoEntry,
};
pub use electrumx::{ElectrumNotification, ElectrumXClient};
pub use header_store::{ConnectBatchResult, ConnectResult, HeaderStore, ParsedHeader};
pub use server_list::{ServerEntry, ServerList, ServerStatus};
pub use whatsonchain::WhatsOnChainClient;
