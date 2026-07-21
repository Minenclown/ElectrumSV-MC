// features/spv_channels.rs — SPV Channels protocol client
//
// Standalone network service module (NOT an OnChainDataDetector).
//
// Implements a client for the BSV SPV Channels REST API: end-to-end encrypted
// P2P messaging channels backed by a relay server. Channels are created with
// a public key; messages are encrypted to the channel's public key and posted
// to the relay, where the recipient polls or streams them.
//
// Reference:
//   - SPV Channels specification (BSV standard)
//   - archive/electrumsv/feature_controller.py
//     (SPVChannelsFeature, feature_id="spv_channels",
//      description="End-to-end encrypted P2P messaging channels")
//
// This module provides the REST client surface. Application-level encryption
// (ECIES / message-level envelope) is layered above this client; the client
// itself transports opaque encrypted blobs.

use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Error type
// ============================================================================

/// Errors that can occur when interacting with an SPV Channels relay.
#[derive(Debug, Error)]
pub enum SpvChannelsError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {status}: {body}")]
    Server { status: u16, body: String },
    #[error("invalid channel id: {0}")]
    InvalidChannelId(String),
    #[error("invalid message id: {0}")]
    InvalidMessageId(String),
    #[error("base64 decode failed: {0}")]
    Base64(String),
}

// ============================================================================
// Data types
// ============================================================================

/// A channel on the SPV Channels relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Channel {
    /// Unique channel id (hex or base64, relay-defined).
    pub channel_id: String,
    /// Public key the channel is encrypted to (hex-encoded).
    pub public_key: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Whether the channel is still accepting new messages.
    pub active: bool,
}

/// A message stored on the relay, awaiting retrieval by the recipient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChannelMessage {
    pub message_id: String,
    pub channel_id: String,
    /// Encrypted payload (base64). The client decrypts after download.
    pub encrypted_payload: String,
    /// Received timestamp (unix seconds).
    pub received: i64,
    /// Whether the message has been marked read.
    pub read: bool,
}

/// Request body for creating a new channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub public_key: String,
    pub description: Option<String>,
}

/// Request body for posting an encrypted message to a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessageRequest {
    pub encrypted_payload: String,
}

// ============================================================================
// Client
// ============================================================================

/// HTTP client for an SPV Channels relay server.
///
/// The relay stores encrypted blobs and forwards them to the channel's
/// recipient. It never sees plaintext — encryption is end-to-end between
/// the sender and the channel's key holder.
pub struct SpvChannelsClient {
    base_url: String,
    http: reqwest::Client,
}

impl SpvChannelsClient {
    /// Create a client for a relay at `base_url`
    /// (e.g. "https://channels.nchain.com").
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    /// Build a client with a custom reqwest::Client (custom TLS, timeouts).
    pub fn with_client(base_url: impl Into<String>, http: reqwest::Client) -> Self {
        Self {
            base_url: base_url.into(),
            http,
        }
    }

    fn url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        format!("{}/{}", base, path.trim_start_matches('/'))
    }

    /// Create a new channel on the relay.
    pub async fn create_channel(
        &self,
        req: &CreateChannelRequest,
    ) -> Result<Channel, SpvChannelsError> {
        let resp = self
            .http
            .post(self.url("api/v1/channel"))
            .json(req)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SpvChannelsError::Server { status, body });
        }
        let channel: Channel = resp.json().await?;
        Ok(channel)
    }

    /// Fetch metadata for an existing channel.
    pub async fn get_channel(&self, channel_id: &str) -> Result<Channel, SpvChannelsError> {
        if channel_id.is_empty() {
            return Err(SpvChannelsError::InvalidChannelId(channel_id.to_string()));
        }
        let resp = self
            .http
            .get(self.url(&format!("api/v1/channel/{}", channel_id)))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SpvChannelsError::Server { status, body });
        }
        let channel: Channel = resp.json().await?;
        Ok(channel)
    }

    /// Post an encrypted message to a channel.
    pub async fn post_message(
        &self,
        channel_id: &str,
        req: &PostMessageRequest,
    ) -> Result<ChannelMessage, SpvChannelsError> {
        if channel_id.is_empty() {
            return Err(SpvChannelsError::InvalidChannelId(channel_id.to_string()));
        }
        // Validate that the payload is base64 before sending.
        if base64::engine::general_purpose::STANDARD
            .decode(&req.encrypted_payload)
            .is_err()
        {
            return Err(SpvChannelsError::Base64(
                "encrypted_payload is not valid base64".to_string(),
            ));
        }

        let resp = self
            .http
            .post(self.url(&format!("api/v1/channel/{}/message", channel_id)))
            .json(req)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SpvChannelsError::Server { status, body });
        }
        let msg: ChannelMessage = resp.json().await?;
        Ok(msg)
    }

    /// List unread messages on a channel.
    pub async fn list_messages(
        &self,
        channel_id: &str,
        unread_only: bool,
    ) -> Result<Vec<ChannelMessage>, SpvChannelsError> {
        if channel_id.is_empty() {
            return Err(SpvChannelsError::InvalidChannelId(channel_id.to_string()));
        }
        let path = if unread_only {
            format!("api/v1/channel/{}/messages?unread=1", channel_id)
        } else {
            format!("api/v1/channel/{}/messages", channel_id)
        };
        let resp = self.http.get(self.url(&path)).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SpvChannelsError::Server { status, body });
        }
        let msgs: Vec<ChannelMessage> = resp.json().await?;
        Ok(msgs)
    }

    /// Mark a message as read on the relay.
    pub async fn mark_read(
        &self,
        channel_id: &str,
        message_id: &str,
    ) -> Result<(), SpvChannelsError> {
        if message_id.is_empty() {
            return Err(SpvChannelsError::InvalidMessageId(message_id.to_string()));
        }
        let resp = self
            .http
            .post(self.url(&format!(
                "api/v1/channel/{}/message/{}/read",
                channel_id, message_id
            )))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SpvChannelsError::Server { status, body });
        }
        Ok(())
    }

    /// Delete a channel and all its messages.
    pub async fn delete_channel(&self, channel_id: &str) -> Result<(), SpvChannelsError> {
        if channel_id.is_empty() {
            return Err(SpvChannelsError::InvalidChannelId(channel_id.to_string()));
        }
        let resp = self
            .http
            .delete(self.url(&format!("api/v1/channel/{}", channel_id)))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(SpvChannelsError::Server { status, body });
        }
        Ok(())
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Count unread messages in a list (client-side convenience).
pub fn count_unread(messages: &[ChannelMessage]) -> usize {
    messages.iter().filter(|m| !m.read).count()
}

/// Find a message by id in a list.
pub fn find_message<'a>(
    messages: &'a [ChannelMessage],
    message_id: &str,
) -> Option<&'a ChannelMessage> {
    messages.iter().find(|m| m.message_id == message_id)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    fn sample_channel() -> Channel {
        Channel {
            channel_id: "ch-abc123".to_string(),
            public_key: "02deadbeef".to_string(),
            description: Some("test channel".to_string()),
            active: true,
        }
    }

    fn sample_message(read: bool) -> ChannelMessage {
        ChannelMessage {
            message_id: "msg-1".to_string(),
            channel_id: "ch-abc123".to_string(),
            encrypted_payload: B64.encode(b"secret payload"),
            received: 1700000000,
            read,
        }
    }

    #[test]
    fn test_count_unread() {
        let msgs = vec![
            sample_message(false),
            sample_message(true),
            sample_message(false),
            sample_message(false),
        ];
        assert_eq!(count_unread(&msgs), 3);
    }

    #[test]
    fn test_find_message() {
        let msgs = vec![sample_message(false), sample_message(true)];
        assert!(find_message(&msgs, "msg-1").is_some());
        assert!(find_message(&msgs, "nonexistent").is_none());
    }

    #[test]
    fn test_post_message_rejects_non_base64() {
        let client = SpvChannelsClient::new("http://localhost:0");
        let req = PostMessageRequest {
            encrypted_payload: "not base64!!".to_string(),
        };
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let err = rt
            .block_on(client.post_message("ch-1", &req))
            .unwrap_err();
        assert!(matches!(err, SpvChannelsError::Base64(_)));
    }

    #[test]
    fn test_empty_channel_id_rejected() {
        let client = SpvChannelsClient::new("http://localhost:0");
        let req = CreateChannelRequest {
            public_key: "02".to_string(),
            description: None,
        };
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let err = rt.block_on(client.get_channel("")).unwrap_err();
        assert!(matches!(err, SpvChannelsError::InvalidChannelId(_)));
    }

    #[test]
    fn test_serde_roundtrip_channel() {
        let ch = sample_channel();
        let json = serde_json::to_string(&ch).expect("serialize");
        let back: Channel = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ch, back);
    }

    #[test]
    fn test_serde_roundtrip_message() {
        let msg = sample_message(false);
        let json = serde_json::to_string(&msg).expect("serialize");
        let back: ChannelMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(msg, back);
    }

    #[test]
    fn test_url_construction() {
        let client = SpvChannelsClient::new("https://channels.example.com/");
        assert_eq!(
            client.url("api/v1/channel/ch-1/message"),
            "https://channels.example.com/api/v1/channel/ch-1/message"
        );
    }
}