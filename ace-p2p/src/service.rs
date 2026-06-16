//! libp2p swarm and gossipsub networking service.
//!
//! `NetworkService` manages the libp2p swarm and communicates with the
//! rest of the node via tokio mpsc channels.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};
use libp2p::identity::Keypair;
use libp2p::mdns;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, SwarmBuilder};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use ace_runtime::crypto::sig_algo;
use ace_runtime::crypto::TaggedSignature;

use crate::behaviour::{AceBehaviour, AceBehaviourEvent};
use crate::config::{
    topic_name, validate_bootnodes, NetworkConfig, TOPIC_BLOCKS, TOPIC_COMMITTEE, TOPIC_FINALITY,
    TOPIC_IDENTITY, TOPIC_MEV_ACE, TOPIC_PRECOMMITS, TOPIC_PREVOTES, TOPIC_PROPOSALS,
    TOPIC_TAKEOVER, TOPIC_TRANSACTIONS,
};
use crate::error::NetworkError;
use crate::messages::{
    EncryptedNetworkEnvelope, IdentityAnnouncement, NetworkMessage, TxFetchFailure,
    MAX_MESSAGE_BYTES,
};
use crate::peer_manager::{PeerManager, PeerSnapshot};
use crate::sync_protocol::SYNC_PROTOCOL;
use crate::tx_fetch_protocol::TX_FETCH_PROTOCOL;

const MAX_PENDING_BLOCK_SYNC_CHANNELS: usize = 256;

/// Load a P2P identity keypair from disk, or generate a new one and persist it.
///
/// The keypair is stored using libp2p's protobuf encoding at `<data_dir>/p2p_identity.key`.
/// If no `data_dir` is configured, a fresh ephemeral keypair is generated each time.
fn write_private_key_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

fn load_or_generate_keypair(data_dir: Option<&std::path::Path>) -> Keypair {
    if let Some(dir) = data_dir {
        let key_path = dir.join("p2p_identity.key");
        // Try loading existing keypair
        if let Ok(bytes) = std::fs::read(&key_path) {
            match Keypair::from_protobuf_encoding(&bytes) {
                Ok(keypair) => {
                    info!("Loaded P2P identity from {}", key_path.display());
                    return keypair;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %key_path.display(),
                        "Failed to decode saved P2P keypair — generating new one"
                    );
                }
            }
        }

        // Generate new keypair and persist
        let keypair = Keypair::generate_ed25519();
        if let Ok(encoded) = keypair.to_protobuf_encoding() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                warn!(error = %e, "Failed to create data dir for P2P identity");
            } else if let Err(e) = write_private_key_file(&key_path, &encoded) {
                warn!(error = %e, path = %key_path.display(), "Failed to save P2P identity");
            } else {
                info!(
                    "Generated and saved new P2P identity to {}",
                    key_path.display()
                );
            }
        }
        keypair
    } else {
        info!("No data_dir configured — using ephemeral P2P identity");
        Keypair::generate_ed25519()
    }
}

pub fn persistent_local_peer_id(data_dir: Option<&std::path::Path>) -> Option<PeerId> {
    data_dir.map(|dir| load_or_generate_keypair(Some(dir)).public().to_peer_id())
}

fn route_inbound_message(
    consensus_tx: &Option<mpsc::Sender<NetworkMessage>>,
    inbound_tx: &mpsc::Sender<NetworkMessage>,
    pending_consensus: &mut VecDeque<NetworkMessage>,
    msg: NetworkMessage,
) {
    if msg.is_consensus() {
        if let Some(tx) = consensus_tx {
            match tx.try_send(msg) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(msg)) => {
                    pending_consensus.push_back(msg);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    debug!("Dropping consensus message: receiver closed");
                }
            }
        } else if let Err(e) = inbound_tx.try_send(msg) {
            debug!(%e, "Dropping consensus message on fallback inbound queue");
        }
        return;
    }

    if let Err(e) = inbound_tx.try_send(msg) {
        debug!(%e, "Dropping non-consensus inbound message: queue full");
    }
}

fn flush_pending_consensus(
    consensus_tx: &Option<mpsc::Sender<NetworkMessage>>,
    inbound_tx: &mpsc::Sender<NetworkMessage>,
    pending_consensus: &mut VecDeque<NetworkMessage>,
) {
    loop {
        let Some(msg) = pending_consensus.pop_front() else {
            break;
        };
        if let Some(tx) = consensus_tx {
            match tx.try_send(msg) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(msg)) => {
                    pending_consensus.push_front(msg);
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
            }
        } else if let Err(tokio::sync::mpsc::error::TrySendError::Full(msg)) =
            inbound_tx.try_send(msg)
        {
            pending_consensus.push_front(msg);
            break;
        }
    }
}

/// P2P network service.
///
/// Runs the libp2p swarm and bridges between gossipsub and the node's
/// internal channel-based communication.
/// Outbound sync request: the node wants to send a BlockSyncRequest to a
/// specific peer (point-to-point via request-response, NOT gossipsub).
pub struct SyncRequestCommand {
    pub peer_id: PeerId,
    pub request: crate::messages::BlockSyncRequest,
}

/// Outbound tx-fetch request: the node wants to fetch missing transactions
/// from a specific peer (the proposer) for compact block reconstruction.
/// Uses String for peer_id so callers don't need libp2p as a dependency.
pub struct TxFetchCommand {
    pub peer_id: String,
    pub request: crate::messages::TxFetchRequest,
}

/// Inbound tx-fetch request: a peer is asking us (the proposer) for
/// transactions they are missing from our compact proposal.
pub struct TxFetchInboundRequest {
    pub peer_id: PeerId,
    pub request: crate::messages::TxFetchRequest,
    pub channel_id: u64,
}

/// Outbound tx-fetch response: the node is responding to an inbound fetch request.
pub struct TxFetchResponseCommand {
    pub channel_id: u64,
    pub response: crate::messages::TxFetchResponse,
}

pub struct NetworkService {
    config: NetworkConfig,
    local_identity: Option<Arc<ace_identity::LoadedIdentity>>,
    peer_count: Arc<AtomicU64>,
    peer_snapshot: Arc<std::sync::RwLock<Vec<PeerSnapshot>>>,
    /// Channel for sending inbound messages to the node.
    inbound_tx: mpsc::Sender<NetworkMessage>,
    /// High-priority channel for consensus messages (Proposal, Prevote, Precommit).
    consensus_tx: Option<mpsc::Sender<NetworkMessage>>,
    /// Dedicated outbound queue for consensus-critical messages.
    consensus_outbound_rx: mpsc::Receiver<NetworkMessage>,
    /// Channel for receiving outbound messages from the node.
    outbound_rx: mpsc::Receiver<NetworkMessage>,
    /// Channel for receiving point-to-point sync requests from the node.
    sync_cmd_rx: mpsc::Receiver<SyncRequestCommand>,
    /// Channel for receiving tx-fetch commands from the node.
    tx_fetch_cmd_rx: mpsc::Receiver<TxFetchCommand>,
    /// Channel for sending inbound tx-fetch requests to the node (proposer side).
    tx_fetch_inbound_tx: mpsc::Sender<TxFetchInboundRequest>,
    /// Channel for receiving tx-fetch responses from the node (proposer side).
    tx_fetch_response_rx: mpsc::Receiver<TxFetchResponseCommand>,
}

impl NetworkService {
    /// Create a new network service.
    ///
    /// Returns the service and channel endpoints for the node:
    /// - `consensus_rx`: high-priority consensus messages (Proposal, Prevote, Precommit)
    /// - `inbound_rx`: all other messages (transactions, sync, finality, etc.)
    /// - `outbound_tx`: sends messages to the network
    pub fn new(
        config: NetworkConfig,
        local_identity: Option<Arc<ace_identity::LoadedIdentity>>,
        peer_count: Arc<AtomicU64>,
        peer_snapshot: Arc<std::sync::RwLock<Vec<PeerSnapshot>>>,
    ) -> (
        Self,
        mpsc::Receiver<NetworkMessage>,
        mpsc::Receiver<NetworkMessage>,
        mpsc::Sender<NetworkMessage>,
        mpsc::Sender<NetworkMessage>,
        mpsc::Sender<SyncRequestCommand>,
        mpsc::Sender<TxFetchCommand>,
        mpsc::Receiver<TxFetchInboundRequest>,
        mpsc::Sender<TxFetchResponseCommand>,
    ) {
        let (inbound_tx, inbound_rx) = mpsc::channel(10_000);
        let (consensus_tx, consensus_rx) = mpsc::channel(1_000);
        let (consensus_outbound_tx, consensus_outbound_rx) = mpsc::channel(2_048);
        let (outbound_tx, outbound_rx) = mpsc::channel(10_000);
        let (sync_cmd_tx, sync_cmd_rx) = mpsc::channel(256);
        let (tx_fetch_cmd_tx, tx_fetch_cmd_rx) = mpsc::channel(256);
        let (tx_fetch_inbound_tx, tx_fetch_inbound_rx) = mpsc::channel(256);
        let (tx_fetch_response_tx, tx_fetch_response_rx) = mpsc::channel(256);

        let service = Self {
            config,
            local_identity,
            peer_count,
            peer_snapshot,
            inbound_tx,
            consensus_tx: Some(consensus_tx),
            consensus_outbound_rx,
            outbound_rx,
            sync_cmd_rx,
            tx_fetch_cmd_rx,
            tx_fetch_inbound_tx,
            tx_fetch_response_rx,
        };

        (
            service,
            consensus_rx,
            inbound_rx,
            outbound_tx,
            consensus_outbound_tx,
            sync_cmd_tx,
            tx_fetch_cmd_tx,
            tx_fetch_inbound_rx,
            tx_fetch_response_tx,
        )
    }

    /// Run the network service (blocking async loop).
    pub async fn run(mut self) -> Result<(), NetworkError> {
        // Validate bootnode addresses include peer IDs for authenticated connections
        if let Err(e) = validate_bootnodes(&self.config.bootnodes) {
            return Err(NetworkError::Transport(e));
        }

        let local_key = load_or_generate_keypair(self.config.data_dir.as_deref());
        let local_peer_id = local_key.public().to_peer_id();
        let local_peer_id_str = local_peer_id.to_string();
        info!(%local_peer_id, name = %self.config.node_name, "Starting P2P service");

        // Configure gossipsub heartbeat well below the slot/block interval so
        // mesh maintenance and IHAVE/IWANT exchanges happen fast enough for
        // consensus messages to propagate within a single round.
        let heartbeat_interval =
            Duration::from_millis((ace_runtime::config::SLOT_DURATION_MS / 4).max(100));
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(heartbeat_interval)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .max_transmit_size(MAX_MESSAGE_BYTES)
            .build()
            .map_err(|e| NetworkError::Transport(e.to_string()))?;

        let gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| NetworkError::Transport(e.to_string()))?;

        let mdns_behaviour = if self.config.enable_mdns {
            info!("mDNS peer discovery enabled (development mode)");
            Some(
                mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                    .map_err(|e| NetworkError::Transport(e.to_string()))?,
            )
        } else {
            info!("mDNS peer discovery disabled");
            None
        };

        // Block sync: point-to-point request-response protocol (replaces gossipsub TOPIC_SYNC).
        // 30 s timeout: the responding node loop may have up to ~1024 RocksDB block reads
        // queued before it can build and enqueue the response, so 10 s was too tight.
        let block_sync = request_response::Behaviour::new(
            [(SYNC_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
        );

        // Tx fetch: point-to-point protocol for compact block proposal reconstruction.
        // Per-attempt timeout = TX_FETCH_PER_ATTEMPT_TIMEOUT_MS:
        //   devnet  : 5 000 ms (original stable value; budget = 10 000 ms so a
        //             single attempt fits within the budget even without retries)
        //   mainnet : TX_FETCH_RECONSTRUCT_BUDGET_MS = 2 000 ms (one attempt can
        //             consume the full budget; deadline stops further retries)
        // The node enforces an absolute deadline (TX_FETCH_RECONSTRUCT_BUDGET_MS)
        // across all attempts; this per-attempt value is a defence-in-depth bound.
        let tx_fetch_per_attempt =
            Duration::from_millis(ace_runtime::config::TX_FETCH_PER_ATTEMPT_TIMEOUT_MS);
        let tx_fetch = request_response::Behaviour::new(
            [(TX_FETCH_PROTOCOL, ProtocolSupport::Full)],
            request_response::Config::default().with_request_timeout(tx_fetch_per_attempt),
        );

        // Consensus votes: direct peer-to-peer delivery of prevotes/precommits.
        // Bypasses gossipsub to eliminate yamux head-of-line blocking.
        let consensus_votes = request_response::Behaviour::new(
            [(
                crate::consensus_votes_protocol::CONSENSUS_VOTES_PROTOCOL,
                ProtocolSupport::Full,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(3)),
        );

        let behaviour = AceBehaviour {
            gossipsub,
            mdns: mdns_behaviour.into(),
            block_sync,
            tx_fetch,
            consensus_votes,
        };

        let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                || {
                    let mut cfg = libp2p::yamux::Config::default();
                    cfg.set_receive_window_size(1024 * 1024); // 1 MiB — reduce backpressure under high TPS
                    cfg
                },
            )
            .map_err(|e| NetworkError::Transport(e.to_string()))?
            .with_dns()
            .map_err(|e| NetworkError::Transport(e.to_string()))?
            .with_behaviour(|_| behaviour)
            .map_err(|e| NetworkError::Transport(e.to_string()))?
            .build();

        // Subscribe to all topics (scoped by chain_id to isolate networks).
        // Block sync now uses request-response, not gossipsub TOPIC_SYNC.
        let chain_id = self.config.chain_id;
        let topic_bases = [
            TOPIC_TRANSACTIONS,
            TOPIC_COMMITTEE,
            TOPIC_BLOCKS,
            TOPIC_FINALITY,
            TOPIC_TAKEOVER,
            TOPIC_IDENTITY,
            TOPIC_PROPOSALS,
            TOPIC_PREVOTES,
            TOPIC_PRECOMMITS,
            TOPIC_MEV_ACE,
        ];
        for base in topic_bases {
            let topic = IdentTopic::new(topic_name(chain_id, base));
            swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&topic)
                .map_err(|e| NetworkError::Publish(e.to_string()))?;
        }

        // Listen on configured address
        let listen_addr: Multiaddr = self
            .config
            .listen_addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| NetworkError::Transport(e.to_string()))?;
        swarm
            .listen_on(listen_addr)
            .map_err(|e| NetworkError::Transport(e.to_string()))?;

        // Connect to bootnodes
        for bootnode in &self.config.bootnodes {
            if let Ok(addr) = bootnode.parse::<Multiaddr>() {
                let _ = swarm.dial(addr);
            }
        }
        for bootstrap_peer in &self.config.bootstrap_peers {
            match bootstrap_peer.parse::<Multiaddr>() {
                Ok(addr) => {
                    let _ = swarm.dial(addr);
                }
                Err(e) => {
                    warn!(
                        peer = bootstrap_peer,
                        error = %e,
                        "Ignoring invalid bootstrap peer address"
                    );
                }
            }
        }

        // Collect all bootstrap addresses for reconnect on disconnection.
        let bootstrap_addrs: Vec<Multiaddr> = self
            .config
            .bootnodes
            .iter()
            .chain(self.config.bootstrap_peers.iter())
            .filter_map(|s| s.parse::<Multiaddr>().ok())
            .collect();

        let mut peer_manager = PeerManager::new(self.config.max_peers);
        self.peer_count
            .store(peer_manager.peer_count() as u64, Ordering::Relaxed);
        // Pending request-response channels: when a peer sends us a BlockSyncRequest,
        // we forward it to the node and store the response channel here. When the node
        // sends back a BlockSyncResponse via outbound_tx, we route it through the channel.
        // The InboundRequestId is stored so we can evict the entry on InboundFailure (timeout),
        // preventing stale entries from blocking future responses for the same start_slot.
        let mut pending_sync_channels: VecDeque<(
            PeerId,
            u64,
            request_response::ResponseChannel<crate::messages::BlockSyncResponse>,
            request_response::InboundRequestId,
        )> = VecDeque::new();
        let mut pending_block_sync_requests: HashMap<
            request_response::OutboundRequestId,
            (PeerId, u64),
        > = HashMap::new();
        // Pending tx-fetch response channels: keyed by auto-incrementing ID.
        // Each entry stores the insertion time alongside the ResponseChannel so
        // a periodic sweep can drop stale entries (node side failed to send back
        // the response command) before the map reaches MAX_PENDING_TX_FETCH.
        // Dropped ResponseChannels cause libp2p to emit InboundFailure on the
        // requester side, which is the correct failure signal — the validator
        // will retry or nil-prevote as appropriate.
        let mut pending_tx_fetch_channels: std::collections::HashMap<
            u64,
            (
                std::time::Instant,
                request_response::ResponseChannel<crate::messages::TxFetchResponse>,
            ),
        > = std::collections::HashMap::new();
        let mut tx_fetch_channel_counter: u64 = 0;
        // How long a pending tx-fetch channel is kept before being evicted.
        // Matches TX_FETCH_RECONSTRUCT_BUDGET_MS so the cleanup fires no later
        // than the node's own reconstruction deadline.
        let tx_fetch_channel_ttl =
            std::time::Duration::from_millis(ace_runtime::config::TX_FETCH_RECONSTRUCT_BUDGET_MS);
        // Independent interval for sweeping stale pending_tx_fetch_channels.
        // Half the TTL so entries are checked at least once per TTL window,
        // bounding worst-case residence to TTL + sweep_period ≈ 1.5 × TTL
        // (an entry inserted just after a sweep lives until the next, then
        // may survive one more if its age is just under TTL at that point).
        let mut tx_fetch_sweep_interval = tokio::time::interval(tx_fetch_channel_ttl / 2);
        let mut pending_tx_fetch_requests: std::collections::HashMap<
            request_response::OutboundRequestId,
            ([u8; 32], PeerId),
        > = std::collections::HashMap::new();
        let mut pending_consensus_inbound = VecDeque::new();
        // Time-based rate limiter for tx gossip: allow at most
        // TX_GOSSIP_WINDOW_MAX tx publishes per TX_GOSSIP_WINDOW.
        // This prevents tx gossip from saturating the yamux transport
        // and starving consensus messages sharing the same TCP connections.
        const TX_GOSSIP_WINDOW: Duration = Duration::from_millis(200);
        // Allow up to 200 tx gossips per 200 ms = ~1000 tx/s.
        // Previously 48 (~240 tx/s) which was below the 400+ TPS PQC load;
        // the shortfall caused validators to miss >40% of txs, making compact
        // proposal reconstruction hit rates drop to 1-40% and triggering the
        // Node-1 sync-loop stall pattern seen under PQC load.
        // At 1000 tx/s × 3 KB/tx (PQC) × 2 peers = 6 MB/s outbound gossip,
        // well within Hetzner's 1 Gbps internal link (125 MB/s).
        const TX_GOSSIP_WINDOW_MAX: usize = 200; // ~1000 tx/s
        let mut tx_gossip_window_start = tokio::time::Instant::now();
        let mut tx_gossip_window_count: usize = 0;
        let mut announce_interval = tokio::time::interval(Duration::from_secs(5));
        let local_identity_ref = self.local_identity.clone();

        // Build a signed identity announcement closure that refreshes the timestamp each tick.
        let make_announcement = {
            let identity = local_identity_ref.clone();
            move || -> Option<IdentityAnnouncement> {
                let identity = identity.as_ref()?;
                let auth_pubkey_bytes = identity.auth_pubkey();
                let tagged_pubkey = ace_runtime::crypto::TaggedPubkey::ed25519(auth_pubkey_bytes);
                let idcom = identity.chain_identity().idcom;
                let timestamp_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                // Build signing message: "ACE-IDANN-V1" || xidentity || idcom || timestamp_ms
                let mut msg = Vec::new();
                msg.extend_from_slice(b"ACE-IDANN-V1");
                msg.extend_from_slice(identity.xidentity().as_bytes());
                msg.extend_from_slice(&idcom);
                msg.extend_from_slice(&timestamp_ms.to_le_bytes());

                let sig_bytes = identity.sign_identity_message(&msg);

                Some(IdentityAnnouncement {
                    xidentity: identity.xidentity().to_string(),
                    idcom: Some(idcom),
                    auth_pubkey: Some(tagged_pubkey),
                    timestamp_ms,
                    signature: Some(sig_bytes.to_vec()),
                })
            }
        };
        let has_local_identity = local_identity_ref.is_some();

        info!("P2P service running");

        loop {
            flush_pending_consensus(
                &self.consensus_tx,
                &self.inbound_tx,
                &mut pending_consensus_inbound,
            );
            tokio::select! {
                // ALL consensus messages go via point-to-point request-response.
                // Gossipsub is unreliable under high tx load (yamux contention
                // drops proposals AND votes), so we bypass it entirely for
                // consensus-critical traffic.
                Some(msg) = self.consensus_outbound_rx.recv() => {
                    use crate::consensus_votes_protocol::DirectVote;
                    let direct_msg = match &msg {
                        NetworkMessage::Prevote(v) => DirectVote::Prevote(v.clone()),
                        NetworkMessage::Precommit(v) => DirectVote::Precommit(v.clone()),
                        NetworkMessage::CommitCertificate(c) => DirectVote::CommitCertificate(c.clone()),
                        NetworkMessage::Proposal(p) => DirectVote::Proposal(p.clone()),
                        NetworkMessage::CompactProposal(cp) => DirectVote::CompactProposal(cp.clone()),
                        other => {
                            warn!("Unexpected consensus outbound message type: {:?}", other.topic());
                            continue;
                        }
                    };
                    for peer_id in peer_manager.connected_peers() {
                        if peer_id != local_peer_id {
                            swarm.behaviour_mut().consensus_votes.send_request(
                                &peer_id,
                                direct_msg.clone(),
                            );
                        }
                    }
                }

                _ = announce_interval.tick(), if has_local_identity => {
                    if let Some(announcement) = make_announcement() {
                        let topic = IdentTopic::new(topic_name(chain_id, TOPIC_IDENTITY));
                        match announcement.to_bytes() {
                            Ok(data) => {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                                    debug!(%e, "Failed to publish identity announcement");
                                }
                            }
                            Err(e) => {
                                warn!(%e, "Failed to serialize identity announcement");
                            }
                        }
                    }
                }

                // Handle swarm events
                event = swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(AceBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { propagation_source, message, .. }
                        )) => {
                            if !peer_manager.is_connected(&propagation_source) {
                                debug!(peer = %propagation_source, "Ignoring message from untracked peer");
                                continue;
                            }
                            if !peer_manager.on_message(&propagation_source) {
                                debug!(peer = %propagation_source, "Rate-limited peer, skipping message");
                                continue;
                            }
                            if let Ok(announcement) = IdentityAnnouncement::from_bytes(&message.data) {
                                if propagation_source != local_peer_id {
                                    // Reject announcements with timestamps too far from current time (±5 minutes).
                                    {
                                        let now_ms = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_millis() as u64;
                                        const MAX_AGE_MS: u64 = 300_000; // 5 minutes
                                        if announcement.timestamp_ms > now_ms.saturating_add(MAX_AGE_MS)
                                            || announcement.timestamp_ms.saturating_add(MAX_AGE_MS) < now_ms
                                        {
                                            warn!(
                                                peer = %propagation_source,
                                                xidentity = %announcement.xidentity,
                                                timestamp_ms = announcement.timestamp_ms,
                                                "Rejecting stale identity announcement"
                                            );
                                            continue;
                                        }
                                    }
                                    // Only accept identity (idcom) when we have a valid signature.
                                    // Unsigned or partial announcements are not trusted for idcom to prevent impersonation.
                                    let verified_idcom = if let (Some(pubkey), Some(sig_bytes), Some(idcom)) =
                                        (&announcement.auth_pubkey, &announcement.signature, &announcement.idcom)
                                    {
                                        let mut msg = Vec::new();
                                        msg.extend_from_slice(b"ACE-IDANN-V1");
                                        msg.extend_from_slice(announcement.xidentity.as_bytes());
                                        msg.extend_from_slice(idcom);
                                        msg.extend_from_slice(&announcement.timestamp_ms.to_le_bytes());
                                        let sig = TaggedSignature {
                                            algorithm: pubkey.algorithm,
                                            bytes: sig_bytes.clone(),
                                        };
                                        if sig_algo::verify_signature(pubkey, &msg, &sig) {
                                            Some(*idcom)
                                        } else {
                                            warn!(
                                                peer = %propagation_source,
                                                xidentity = %announcement.xidentity,
                                                "Rejecting identity announcement with invalid signature"
                                            );
                                            continue;
                                        }
                                    } else {
                                        if announcement.signature.is_some() || announcement.auth_pubkey.is_some() {
                                            warn!(
                                                peer = %propagation_source,
                                                xidentity = %announcement.xidentity,
                                                "Identity announcement has partial signature fields — rejecting idcom update"
                                            );
                                        }
                                        None
                                    };

                                    peer_manager.set_identity(
                                        &propagation_source,
                                        announcement.xidentity,
                                        verified_idcom,
                                    );
                                }
                                continue;
                            }

                            if let Some(identity) = &self.local_identity {
                                if let Ok(envelope) = EncryptedNetworkEnvelope::from_bytes(&message.data) {
                                    if envelope.recipient_peer_id != local_peer_id_str {
                                        continue;
                                    }
                                    match identity.decrypt_payload(&envelope.payload) {
                                        Ok(plaintext) => match NetworkMessage::from_bytes(&plaintext) {
                                            Ok(msg) => {
                                                debug!(?msg, sender = envelope.sender_peer_id, "Received encrypted network message");
                                                route_inbound_message(
                                                    &self.consensus_tx,
                                                    &self.inbound_tx,
                                                    &mut pending_consensus_inbound,
                                                    msg,
                                                );
                                            }
                                            Err(e) => {
                                                warn!(%e, "Failed to deserialize decrypted network message");
                                            }
                                        },
                                        Err(e) => {
                                            warn!(error = %e, sender = envelope.sender_peer_id, "Failed to decrypt network envelope");
                                        }
                                    }
                                    continue;
                                }
                            }

                            match NetworkMessage::from_bytes(&message.data) {
                                Ok(mut msg) => {
                                    // Inject the authenticated gossipsub author so the node
                                    // can fetch missing txs from the original proposer rather
                                    // than the last relay hop.
                                    let source_peer = message.source.as_ref().map(ToString::to_string);
                                    if let NetworkMessage::CompactProposal(ref mut cp) = msg {
                                        cp.proposer_peer_id = source_peer.clone();
                                    }
                                    // Inject source peer for PQC stripped txs so the node
                                    // can prefetch the full credential immediately.
                                    if let NetworkMessage::NewTransaction { ref mut source_peer_id, .. } = msg {
                                        *source_peer_id = source_peer;
                                    }
                                    debug!(?msg, "Received plaintext network message");
                                    // Route consensus messages to high-priority channel
                                    route_inbound_message(
                                        &self.consensus_tx,
                                        &self.inbound_tx,
                                        &mut pending_consensus_inbound,
                                        msg,
                                    );
                                }
                                Err(e) => {
                                    warn!(%e, "Failed to deserialize network message");
                                }
                            }
                        }
                        SwarmEvent::ConnectionEstablished {
                            peer_id,
                            endpoint,
                            num_established,
                            ..
                        } => {
                            let direction = if endpoint.is_listener() { "incoming" } else { "outgoing" };
                            let remote_addr = endpoint.get_remote_address().to_string();
                            if !peer_manager.on_connected(
                                peer_id,
                                num_established.get(),
                                remote_addr,
                                direction.to_string(),
                            ) {
                                warn!(%peer_id, max_peers = self.config.max_peers, "Peer limit reached; disconnecting excess peer");
                                let _ = swarm.disconnect_peer_id(peer_id);
                            } else {
                                self.peer_count
                                    .store(peer_manager.peer_count() as u64, Ordering::Relaxed);
                                if let Ok(mut snapshot) = self.peer_snapshot.write() {
                                    *snapshot = peer_manager.snapshots();
                                }
                                // Ensure the peer is in the gossipsub mesh so messages flow
                                // immediately. Without this, bootnode-only connections (no mDNS)
                                // rely on organic mesh grafting which may never happen with few peers.
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);

                                // add_explicit_peer above ensures gossipsub delivers messages
                                // in both directions on the single underlying connection.
                                // Do NOT dial back using endpoint.get_remote_address() — that
                                // returns the ephemeral source port, not the listen port, so
                                // the dial always fails.  More importantly, dialing back on a
                                // simultaneous-open causes libp2p to drop one of the two
                                // in-progress connections, leaving nodes with fewer peers than
                                // expected after startup.
                                info!(%peer_id, direction, "Peer connected and added to gossipsub mesh");
                            }
                        }
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            num_established,
                            ..
                        } => {
                            peer_manager.on_disconnected(&peer_id, num_established);
                            pending_block_sync_requests.retain(|_, (pending_peer, _)| {
                                *pending_peer != peer_id
                            });
                            self.peer_count
                                .store(peer_manager.peer_count() as u64, Ordering::Relaxed);
                            if let Ok(mut snapshot) = self.peer_snapshot.write() {
                                *snapshot = peer_manager.snapshots();
                            }
                            // If we dropped below the bootstrap target, re-dial all bootstrap
                            // addresses.  This recovers from simultaneous-dial collisions at
                            // startup (where libp2p drops one side) and from transient
                            // disconnections during operation.  libp2p deduplicates dials to
                            // already-connected peers, so redundant calls are harmless.
                            if peer_manager.peer_count() < bootstrap_addrs.len() {
                                for addr in &bootstrap_addrs {
                                    let _ = swarm.dial(addr.clone());
                                }
                            }
                        }
                        SwarmEvent::Behaviour(AceBehaviourEvent::Mdns(
                            mdns::Event::Discovered(peers)
                        )) => {
                            if self.config.enable_mdns {
                                for (peer_id, addr) in peers {
                                    debug!(%peer_id, %addr, "mDNS discovered peer");
                                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                    if !peer_manager.is_connected(&peer_id) {
                                        info!(%peer_id, %addr, "mDNS discovered peer — dialing immediately");
                                        let _ = swarm.dial(addr.clone());
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(AceBehaviourEvent::Mdns(
                            mdns::Event::Expired(peers)
                        )) => {
                            if self.config.enable_mdns {
                                for (peer_id, _) in peers {
                                    debug!(%peer_id, "mDNS peer expired");
                                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                }
                            }
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!(%address, "Listening on");
                        }
                        // Handle block sync request-response events
                        SwarmEvent::Behaviour(AceBehaviourEvent::BlockSync(event)) => {
                            match event {
                                request_response::Event::Message { peer, message } => {
                                    match message {
                                        request_response::Message::Request { mut request, channel, request_id } => {
                                            debug!(%peer, start_slot = request.start_slot, "Received block sync request (P2P)");
                                            if pending_sync_channels.len() >= MAX_PENDING_BLOCK_SYNC_CHANNELS {
                                                warn!(
                                                    %peer,
                                                    start_slot = request.start_slot,
                                                    pending = pending_sync_channels.len(),
                                                    "Dropping block sync request: pending response channels at capacity"
                                                );
                                                continue;
                                            }
                                            let start_slot = request.start_slot;
                                            // Stamp the requester peer_id so the node can echo it back
                                            // and the network layer can match by (peer_id, start_slot).
                                            request.requester_peer_id = Some(peer.to_string());
                                            // Forward to node via inbound channel; the node will build and send the response.
                                            match self.inbound_tx.try_send(NetworkMessage::BlockSyncRequest(request)) {
                                                Ok(()) => {
                                                    // Store the channel (with its request_id for failure cleanup) so we can
                                                    // route the response when the node sends back a BlockSyncResponse.
                                                    pending_sync_channels.push_back((peer, start_slot, channel, request_id));
                                                }
                                                Err(e) => {
                                                    warn!(
                                                        %peer,
                                                        start_slot,
                                                        %e,
                                                        "Dropping block sync request: node inbound queue unavailable"
                                                    );
                                                }
                                            }
                                        }
                                        request_response::Message::Response { request_id, response } => {
                                            debug!(%peer, records = response.records.len(), "Received block sync response (P2P)");
                                            pending_block_sync_requests.remove(&request_id);
                                            let _ = self.inbound_tx.try_send(
                                                NetworkMessage::BlockSyncResponse(response)
                                            );
                                        }
                                    }
                                }
                                request_response::Event::OutboundFailure { peer, request_id, error } => {
                                    pending_block_sync_requests.remove(&request_id);
                                    debug!(%peer, %error, "Block sync outbound failure");
                                }
                                request_response::Event::InboundFailure { peer, request_id, error } => {
                                    debug!(%peer, %error, "Block sync inbound failure");
                                    // The response channel for this request has timed out / failed.
                                    // Remove it from pending_sync_channels so it cannot block
                                    // future responses for the same start_slot.
                                    pending_sync_channels.retain(|(_, _, _, rid)| *rid != request_id);
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        // Handle tx-fetch request-response events (compact block reconstruction)
                        SwarmEvent::Behaviour(AceBehaviourEvent::TxFetch(event)) => {
                            match event {
                                request_response::Event::Message { peer, message } => {
                                    match message {
                                        request_response::Message::Request { request, channel, .. } => {
                                            debug!(%peer, missing = request.tx_hashes().len(), "Received tx-fetch request");
                                            const MAX_PENDING_TX_FETCH: usize = 1000;
                                            if pending_tx_fetch_channels.len() >= MAX_PENDING_TX_FETCH {
                                                warn!(%peer, "pending_tx_fetch_channels at capacity; dropping new tx-fetch request");
                                                continue;
                                            }
                                            let channel_id = tx_fetch_channel_counter;
                                            tx_fetch_channel_counter += 1;
                                            pending_tx_fetch_channels.insert(channel_id, (std::time::Instant::now(), channel));
                                            if let Err(e) = self.tx_fetch_inbound_tx.try_send(TxFetchInboundRequest {
                                                peer_id: peer,
                                                request,
                                                channel_id,
                                            }) {
                                                // Node-side channel is full or closed.  Remove the
                                                // pending entry immediately — dropping the
                                                // ResponseChannel causes libp2p to send an
                                                // InboundFailure to the requesting peer, which is
                                                // the correct signal for it to retry or nil-prevote.
                                                pending_tx_fetch_channels.remove(&channel_id);
                                                warn!(%peer, %e, "tx-fetch inbound channel full; dropped pending response channel");
                                            }
                                        }
                                        request_response::Message::Response { request_id, response } => {
                                            debug!(%peer, txs = response.transactions_wire().len(), "Received tx-fetch response");
                                            pending_tx_fetch_requests.remove(&request_id);
                                            // Route to consensus channel as a special message
                                            route_inbound_message(
                                                &self.consensus_tx,
                                                &self.inbound_tx,
                                                &mut pending_consensus_inbound,
                                                NetworkMessage::TxFetchResponse(response),
                                            );
                                        }
                                    }
                                }
                                request_response::Event::OutboundFailure { peer, request_id, error } => {
                                    debug!(%peer, %error, "Tx-fetch outbound failure");
                                    if let Some((block_hash, requested_peer)) =
                                        pending_tx_fetch_requests.remove(&request_id)
                                    {
                                        route_inbound_message(
                                            &self.consensus_tx,
                                            &self.inbound_tx,
                                            &mut pending_consensus_inbound,
                                            NetworkMessage::TxFetchFailure(TxFetchFailure {
                                                block_hash,
                                                peer_id: requested_peer.to_string(),
                                                error: error.to_string(),
                                            }),
                                        );
                                    }
                                }
                                request_response::Event::InboundFailure { peer, error, .. } => {
                                    debug!(%peer, %error, "Tx-fetch inbound failure");
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        // Handle direct consensus message delivery (point-to-point)
                        SwarmEvent::Behaviour(AceBehaviourEvent::ConsensusVotes(event)) => {
                            match event {
                                request_response::Event::Message { peer, message } => {
                                    match message {
                                        request_response::Message::Request { request, channel, .. } => {
                                            use crate::consensus_votes_protocol::DirectVote;
                                            let mut net_msg = match request {
                                                DirectVote::Prevote(v) => NetworkMessage::Prevote(v),
                                                DirectVote::Precommit(v) => NetworkMessage::Precommit(v),
                                                DirectVote::CommitCertificate(c) => NetworkMessage::CommitCertificate(c),
                                                DirectVote::Proposal(p) => NetworkMessage::Proposal(p),
                                                DirectVote::CompactProposal(cp) => NetworkMessage::CompactProposal(cp),
                                            };
                                            // Stamp proposer_peer_id so tx-fetch knows where to request missing txs.
                                            if let NetworkMessage::CompactProposal(ref mut cp) = net_msg {
                                                cp.proposer_peer_id = Some(peer.to_string());
                                            }
                                            route_inbound_message(
                                                &self.consensus_tx,
                                                &self.inbound_tx,
                                                &mut pending_consensus_inbound,
                                                net_msg,
                                            );
                                            // Send ACK
                                            let _ = swarm.behaviour_mut().consensus_votes.send_response(
                                                channel,
                                                crate::consensus_votes_protocol::VoteAck,
                                            );
                                        }
                                        request_response::Message::Response { .. } => {
                                            // ACK received — nothing to do.
                                        }
                                    }
                                }
                                request_response::Event::OutboundFailure { peer, error, .. } => {
                                    debug!(%peer, %error, "Direct vote delivery failed");
                                }
                                request_response::Event::InboundFailure { peer, error, .. } => {
                                    debug!(%peer, %error, "Direct vote inbound failure");
                                }
                                request_response::Event::ResponseSent { .. } => {}
                            }
                        }
                        _ => {}
                    }
                }

                // Handle point-to-point sync request commands from the node
                Some(cmd) = self.sync_cmd_rx.recv() => {
                    debug!(peer = %cmd.peer_id, start_slot = cmd.request.start_slot, "Sending P2P sync request");
                    swarm.behaviour_mut().block_sync.send_request(&cmd.peer_id, cmd.request);
                }

                // Handle tx-fetch outbound requests from the node (receiver side)
                Some(cmd) = self.tx_fetch_cmd_rx.recv() => {
                    match cmd.peer_id.parse::<PeerId>() {
                        Ok(peer_id) => {
                            debug!(peer = %peer_id, missing = cmd.request.tx_hashes().len(), "Sending tx-fetch request");
                            // For routing failure messages, extract block_hash if CompactBlock.
                            let block_hash_for_failure = match &cmd.request {
                                crate::messages::TxFetchRequest::CompactBlock { block_hash, .. } => *block_hash,
                                crate::messages::TxFetchRequest::Mempool { .. } => [0u8; 32],
                            };
                            let request_id =
                                swarm.behaviour_mut().tx_fetch.send_request(&peer_id, cmd.request);
                            pending_tx_fetch_requests.insert(request_id, (block_hash_for_failure, peer_id));
                        }
                        Err(e) => {
                            debug!(peer = %cmd.peer_id, %e, "Invalid PeerId in tx-fetch command");
                            let block_hash_for_failure = match &cmd.request {
                                crate::messages::TxFetchRequest::CompactBlock { block_hash, .. } => *block_hash,
                                crate::messages::TxFetchRequest::Mempool { .. } => [0u8; 32],
                            };
                            route_inbound_message(
                                &self.consensus_tx,
                                &self.inbound_tx,
                                &mut pending_consensus_inbound,
                                NetworkMessage::TxFetchFailure(TxFetchFailure {
                                    block_hash: block_hash_for_failure,
                                    peer_id: cmd.peer_id,
                                    error: format!("invalid proposer peer id: {e}"),
                                }),
                            );
                        }
                    }
                }

                // Handle tx-fetch responses from the node (proposer side)
                Some(cmd) = self.tx_fetch_response_rx.recv() => {
                    if let Some((_inserted_at, channel)) = pending_tx_fetch_channels.remove(&cmd.channel_id) {
                        if let Err(_resp) = swarm.behaviour_mut().tx_fetch.send_response(channel, cmd.response) {
                            debug!(channel_id = cmd.channel_id, "Failed to send tx-fetch response (channel closed)");
                        }
                    } else {
                        debug!(channel_id = cmd.channel_id, "No pending tx-fetch channel for response");
                    }
                }

                // Independent TTL sweep for pending_tx_fetch_channels.
                // Runs regardless of whether the response path is active, so
                // stale channels are evicted even when the node side is stuck
                // or the response_rx has no traffic.
                _ = tx_fetch_sweep_interval.tick() => {
                    let now = std::time::Instant::now();
                    let before = pending_tx_fetch_channels.len();
                    pending_tx_fetch_channels.retain(|_, (inserted_at, _)| {
                        now.duration_since(*inserted_at) < tx_fetch_channel_ttl
                    });
                    let evicted = before - pending_tx_fetch_channels.len();
                    if evicted > 0 {
                        warn!(evicted, "Evicted stale pending tx-fetch channels (node response timed out)");
                    }
                }

                // Handle outbound messages from the node.
                // Drain pending outbound messages, but rate-limit transaction
                // gossip to avoid saturating the yamux transport and starving
                // consensus messages at the TCP layer.
                Some(first_msg) = self.outbound_rx.recv() => {
                    let mut batch = vec![first_msg];
                    const MAX_OUTBOUND_DRAIN: usize = 64;
                    for _ in 0..MAX_OUTBOUND_DRAIN {
                        match self.outbound_rx.try_recv() {
                            Ok(m) => batch.push(m),
                            Err(_) => break,
                        }
                    }
                    // Partition: non-tx messages always published; tx messages
                    // at the tail so they get dropped first under rate limit.
                    batch.sort_by_key(|m| match m {
                        _ if m.is_consensus() => 0u8,
                        NetworkMessage::NewTransaction { .. } => 2,
                        _ => 1,
                    });
                    // Reset the time-based window if enough time has elapsed.
                    let now = tokio::time::Instant::now();
                    if now.duration_since(tx_gossip_window_start) >= TX_GOSSIP_WINDOW {
                        tx_gossip_window_start = now;
                        tx_gossip_window_count = 0;
                    }
                    for msg in batch {
                    // Time-based rate limit: drop tx gossip exceeding the
                    // per-window budget.  Transactions propagate via block
                    // proposals anyway; mempool sharing is best-effort.
                    if matches!(&msg, NetworkMessage::NewTransaction { .. }) {
                        tx_gossip_window_count += 1;
                        if tx_gossip_window_count > TX_GOSSIP_WINDOW_MAX {
                            continue; // drop — proposals carry full block data
                        }
                    }
                    if let NetworkMessage::DialPeer { addr } = &msg {
                        match addr.parse::<Multiaddr>() {
                            Ok(addr) => {
                                debug!(%addr, "Dialing discovered public peer");
                                let _ = swarm.dial(addr);
                            }
                            Err(e) => {
                                warn!(peer = addr, error = %e, "Ignoring invalid discovered peer address");
                            }
                        }
                        continue;
                    }
                    if let NetworkMessage::BlockSyncRequest(request) = &msg {
                        let peers = peer_manager.connected_peers();
                        if peers.is_empty() {
                            debug!(
                                start_slot = request.start_slot,
                                "Dropping block sync request: no connected peers"
                            );
                        } else {
                            for peer_id in peers {
                                if pending_block_sync_requests
                                    .values()
                                    .any(|(pending_peer, _)| *pending_peer == peer_id)
                                {
                                    debug!(
                                        peer = %peer_id,
                                        start_slot = request.start_slot,
                                        "Skipping block sync request: peer already has an in-flight request"
                                    );
                                    continue;
                                }
                                debug!(
                                    peer = %peer_id,
                                    start_slot = request.start_slot,
                                    "Sending block sync request (P2P)"
                                );
                                let request_id = swarm
                                    .behaviour_mut()
                                    .block_sync
                                    .send_request(&peer_id, request.clone());
                                pending_block_sync_requests
                                    .insert(request_id, (peer_id, request.start_slot));
                            }
                        }
                        continue;
                    }

                    // Intercept BlockSyncResponse: send via pending request-response channel.
                    // Match by (peer_id, start_slot) to avoid responding to the wrong peer
                    // when multiple peers request the same start_slot concurrently.
                    if let NetworkMessage::BlockSyncResponse(response) = &msg {
                        // response.peer_id identifies which peer's request this answers.
                        let position = if let Some(ref resp_peer_id) = response.peer_id {
                            pending_sync_channels
                                .iter()
                                .position(|(peer, start_slot, _, _)| {
                                    *start_slot == response.start_slot
                                        && peer.to_string() == *resp_peer_id
                                })
                        } else {
                            // Fallback: match by start_slot only (older callers).
                            pending_sync_channels
                                .iter()
                                .position(|(_, start_slot, _, _)| *start_slot == response.start_slot)
                        };
                        if let Some(position) = position {
                            let (peer, start_slot, channel, _) =
                                pending_sync_channels.remove(position).expect("position exists");
                            if let Err(resp) = swarm
                                .behaviour_mut()
                                .block_sync
                                .send_response(channel, response.clone())
                            {
                                debug!(
                                    %peer,
                                    start_slot,
                                    records = resp.records.len(),
                                    "Failed to send sync response (channel closed)"
                                );
                            }
                        } else {
                            debug!(
                                start_slot = response.start_slot,
                                records = response.records.len(),
                                "Dropping sync response: no pending request channel"
                            );
                        }
                        continue;
                    }

                    let topic_str = topic_name(chain_id, msg.topic());
                    let plaintext = match msg.to_bytes() {
                        Ok(data) => data,
                        Err(e) => {
                            warn!(%e, "Failed to serialize outbound message");
                            continue;
                        }
                    };

                    // Private messages (e.g. IdentityTakeover) are encrypted
                    // per-peer.  Public messages (txs, blocks, finality certs,
                    // consensus votes, committee approvals) are broadcast once
                    // in plaintext — O(1) instead of O(n) encryption + publish.
                    if let Some(identity) = &self.local_identity {
                        if !msg.is_public() {
                        let recipients = peer_manager.connected_peer_xidentities();
                        let sender_idcom = Some(identity.chain_identity().idcom);
                        for (peer_id, xidentity) in recipients {
                            if peer_id.to_string() == local_peer_id_str {
                                continue;
                            }
                            match identity.encrypt_for_recipient(&xidentity, &plaintext) {
                                Ok(payload) => {
                                    let envelope = EncryptedNetworkEnvelope {
                                        recipient_peer_id: peer_id.to_string(),
                                        sender_peer_id: local_peer_id_str.clone(),
                                        sender_idcom,
                                        payload,
                                    };
                                    let topic = IdentTopic::new(topic_str.clone());
                                    match envelope.to_bytes() {
                                        Ok(data) => {
                                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                                                debug!(%e, recipient = %peer_id, "Failed to publish encrypted message");
                                            }
                                        }
                                        Err(e) => {
                                            warn!(%e, recipient = %peer_id, "Failed to serialize encrypted message");
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, recipient = %peer_id, "Failed to encrypt message for peer");
                                }
                            }
                        }
                        continue;
                    }
                    }

                    let topic = IdentTopic::new(topic_str);
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, plaintext) {
                        debug!(%e, "Failed to publish message (may have no peers)");
                    }
                    } // end for msg in batch
                }
            }
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}
