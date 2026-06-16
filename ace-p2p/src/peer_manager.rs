//! Connected peer tracking.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;

/// Maximum messages per second per peer before rate limiting.
const MAX_MESSAGES_PER_SECOND: u32 = 200;

/// Tracks connected peers and their metadata.
pub struct PeerManager {
    peers: HashMap<PeerId, PeerInfo>,
    max_peers: usize,
    /// Per-peer rate limiting: (window start, message count in current window).
    rate_limits: HashMap<PeerId, (Instant, u32)>,
}

/// Information about a connected peer.
pub struct PeerInfo {
    /// When the peer connected.
    pub connected_at: Instant,
    /// Number of currently established connections for this peer.
    pub connections: usize,
    /// Number of messages received from this peer.
    pub messages_received: u64,
    /// The peer's advertised xidentity for transport E2EE.
    pub xidentity: Option<String>,
    /// Optional chain identity commitment associated with the peer.
    pub idcom: Option<[u8; 32]>,
    /// Remote multiaddr observed by libp2p for the active connection.
    pub remote_addr: String,
    /// Connection direction from the local node's perspective.
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub peer_id: String,
    pub remote_addr: String,
    pub direction: String,
    pub connected_secs: u64,
    pub messages_received: u64,
}

impl PeerManager {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
            rate_limits: HashMap::new(),
        }
    }

    /// Record a new peer connection.
    pub fn on_connected(
        &mut self,
        peer_id: PeerId,
        num_established: u32,
        remote_addr: String,
        direction: String,
    ) -> bool {
        if let Some(info) = self.peers.get_mut(&peer_id) {
            info.connections = (num_established as usize).max(1);
            info.remote_addr = remote_addr;
            info.direction = direction;
            return true;
        }

        if self.peers.len() >= self.max_peers {
            return false;
        }

        self.peers.insert(
            peer_id,
            PeerInfo {
                connected_at: Instant::now(),
                connections: (num_established as usize).max(1),
                messages_received: 0,
                xidentity: None,
                idcom: None,
                remote_addr,
                direction,
            },
        );
        true
    }

    /// Record a peer disconnection.
    pub fn on_disconnected(&mut self, peer_id: &PeerId, remaining_established: u32) {
        if remaining_established > 0 {
            if let Some(info) = self.peers.get_mut(peer_id) {
                info.connections = remaining_established as usize;
            }
            return;
        }

        self.peers.remove(peer_id);
        self.rate_limits.remove(peer_id);
    }

    /// Record a message from a peer. Returns false if rate-limited.
    pub fn on_message(&mut self, peer_id: &PeerId) -> bool {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.messages_received += 1;
        }
        let now = Instant::now();
        let entry = self.rate_limits.entry(*peer_id).or_insert((now, 0));
        if now.duration_since(entry.0).as_secs() >= 1 {
            // New window
            *entry = (now, 1);
            true
        } else {
            entry.1 += 1;
            entry.1 <= MAX_MESSAGES_PER_SECOND
        }
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get all connected peer IDs.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }

    pub fn snapshots(&self) -> Vec<PeerSnapshot> {
        self.peers
            .iter()
            .map(|(peer_id, info)| PeerSnapshot {
                peer_id: peer_id.to_string(),
                remote_addr: info.remote_addr.clone(),
                direction: info.direction.clone(),
                connected_secs: info.connected_at.elapsed().as_secs(),
                messages_received: info.messages_received,
            })
            .collect()
    }

    /// Set peer's xidentity and optionally update idcom.
    /// When `idcom` is `None`, the existing idcom is left unchanged (used when announcement was not verified).
    pub fn set_identity(&mut self, peer_id: &PeerId, xidentity: String, idcom: Option<[u8; 32]>) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.xidentity = Some(xidentity);
            if let Some(idcom) = idcom {
                info.idcom = Some(idcom);
            }
        }
    }

    pub fn connected_peer_xidentities(&self) -> Vec<(PeerId, String)> {
        self.peers
            .iter()
            .filter_map(|(peer_id, info)| {
                info.xidentity
                    .clone()
                    .map(|xidentity| (*peer_id, xidentity))
            })
            .collect()
    }

    /// Check if a peer is connected.
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.peers.contains_key(peer_id)
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new(50)
    }
}
