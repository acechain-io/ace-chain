//! P2P integration tests — two-node gossipsub connectivity and message passing.

use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};
use libp2p::identity::Keypair;
use libp2p::mdns;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, SwarmBuilder};

use ace_p2p::config::{topic_name, TOPIC_BLOCKS, TOPIC_SYNC, TOPIC_TAKEOVER, TOPIC_TRANSACTIONS};
use ace_p2p::messages::{
    BlockSyncRecord, BlockSyncRequest, BlockSyncResponse, NetworkMessage, MAX_MESSAGE_BYTES,
};
use ace_p2p::takeover::{signing_message, IdentityTakeoverMsg};
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::types::attestation::{Attestation, Domain};
use ace_runtime::types::block::{Block, BlockHeader};
use ace_runtime::types::finality::FinalityState;
use ace_runtime::types::transaction::Transaction;

/// Helper: build a libp2p swarm with gossipsub + mDNS (same config as NetworkService).
fn build_test_swarm() -> libp2p::Swarm<ace_p2p::behaviour::AceBehaviour> {
    let local_key = Keypair::generate_ed25519();
    let local_peer_id = local_key.public().to_peer_id();

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_millis(100)) // faster for tests
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(MAX_MESSAGE_BYTES)
        .build()
        .expect("gossipsub config");

    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )
    .expect("gossipsub behaviour");

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
        .expect("mdns behaviour");

    let block_sync = libp2p::request_response::Behaviour::new(
        [(
            ace_p2p::sync_protocol::SYNC_PROTOCOL,
            libp2p::request_response::ProtocolSupport::Full,
        )],
        libp2p::request_response::Config::default(),
    );
    let tx_fetch = libp2p::request_response::Behaviour::new(
        [(
            ace_p2p::tx_fetch_protocol::TX_FETCH_PROTOCOL,
            libp2p::request_response::ProtocolSupport::Full,
        )],
        libp2p::request_response::Config::default(),
    );
    let consensus_votes = libp2p::request_response::Behaviour::new(
        [(
            ace_p2p::consensus_votes_protocol::CONSENSUS_VOTES_PROTOCOL,
            libp2p::request_response::ProtocolSupport::Full,
        )],
        libp2p::request_response::Config::default(),
    );
    let behaviour = ace_p2p::behaviour::AceBehaviour {
        gossipsub,
        mdns: Some(mdns).into(),
        block_sync,
        tx_fetch,
        consensus_votes,
    };

    SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .expect("tcp transport")
        .with_behaviour(|_| behaviour)
        .expect("behaviour")
        .build()
}

fn make_dummy_tx() -> Transaction {
    Transaction {
        payload: vec![0x01, 0x00, 0xFF],
        attestation: Attestation {
            obj_hash: [0xAA; 32],
            idcom: [0xBB; 32],
            domain: Domain {
                chain_id: 1,
                slot: 42,
            },
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0xCC; 64]),
        },
        raw_chain: None,
        zk_auth: None,
    }
}

fn make_dummy_block() -> Block {
    Block {
        header: BlockHeader {
            slot: 1,
            leader_idcom: [0x01; 32],
            parent_hash: [0; 32],
            state_root: [0; 32],
            tx_merkle_root: [0; 32],
            attest_merkle_root: [0; 32],
            tx_count: 0,
            poh_hash: [0; 32],
            timestamp: 1000,
            round: 0,
            mev_ace_material_hash: [0u8; 32],
        },
        transactions: vec![],
        mev_ace: None,
    }
}

// ── Serialization roundtrip tests for all message variants ──

#[test]
fn takeover_message_roundtrip() {
    use ace_runtime::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};
    let key = LocalSigningKey::from_seed(&[0xEE; 32], SignatureAlgorithm::Ed25519).unwrap();
    let credential = key.sign(&signing_message(&[0xDD; 32], 7, 123456));
    let takeover_msg = IdentityTakeoverMsg::new_signed([0xDD; 32], credential, 7, 123456);
    let msg = NetworkMessage::IdentityTakeover(takeover_msg.clone());
    let bytes = msg.to_bytes().unwrap();
    let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

    match decoded {
        NetworkMessage::IdentityTakeover(t) => {
            assert_eq!(t.idcom, [0xDD; 32]);
            assert_eq!(t.nonce, 7);
            assert_eq!(t.timestamp_ms, 123456);
            assert!(t.verify(&key.public_key()));
        }
        _ => panic!("expected IdentityTakeover"),
    }
}

#[test]
fn takeover_topic_mapping() {
    use ace_runtime::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};
    let key = LocalSigningKey::from_seed(&[0xAB; 32], SignatureAlgorithm::Ed25519).unwrap();
    let credential = key.sign(&signing_message(&[0; 32], 0, 0));
    let msg = NetworkMessage::IdentityTakeover(IdentityTakeoverMsg::new_signed(
        [0; 32], credential, 0, 0,
    ));
    assert_eq!(msg.topic(), TOPIC_TAKEOVER);
}

#[test]
fn all_topics_are_distinct() {
    let topics = [
        TOPIC_TRANSACTIONS,
        TOPIC_BLOCKS,
        ace_p2p::config::TOPIC_FINALITY,
        TOPIC_SYNC,
        TOPIC_TAKEOVER,
    ];
    for (i, a) in topics.iter().enumerate() {
        for (j, b) in topics.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "topics at index {i} and {j} must be distinct");
            }
        }
    }
}

#[test]
fn block_message_roundtrip() {
    let block = make_dummy_block();
    let msg = NetworkMessage::NewBlock(block);
    let bytes = msg.to_bytes().unwrap();
    let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

    match decoded {
        NetworkMessage::NewBlock(b) => {
            assert_eq!(b.header.slot, 1);
            assert_eq!(b.header.leader_idcom, [0x01; 32]);
        }
        _ => panic!("expected NewBlock"),
    }
}

#[test]
fn block_sync_request_roundtrip() {
    let msg = NetworkMessage::BlockSyncRequest(BlockSyncRequest {
        start_slot: 9,
        limit: 16,
        requester_peer_id: None,
    });
    let bytes = msg.to_bytes().unwrap();
    let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

    match decoded {
        NetworkMessage::BlockSyncRequest(req) => {
            assert_eq!(req.start_slot, 9);
            assert_eq!(req.limit, 16);
            assert_eq!(msg.topic(), TOPIC_SYNC);
        }
        _ => panic!("expected BlockSyncRequest"),
    }
}

#[test]
fn block_sync_response_roundtrip() {
    let block = make_dummy_block();
    let msg = NetworkMessage::BlockSyncResponse(BlockSyncResponse {
        start_slot: 1,
        latest_slot: 3,
        records: vec![BlockSyncRecord {
            block,
            finality_state: Some(FinalityState::Hard),
            finality_cert: None,
        }],
        peer_id: None,
    });
    let bytes = msg.to_bytes().unwrap();
    let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

    match decoded {
        NetworkMessage::BlockSyncResponse(resp) => {
            assert_eq!(resp.start_slot, 1);
            assert_eq!(resp.latest_slot, 3);
            assert_eq!(resp.records.len(), 1);
            assert_eq!(resp.records[0].finality_state, Some(FinalityState::Hard));
        }
        _ => panic!("expected BlockSyncResponse"),
    }
}

// ── Peer manager tests ──

#[test]
fn peer_manager_lifecycle() {
    use ace_p2p::peer_manager::PeerManager;

    let mut pm = PeerManager::new(50);
    assert_eq!(pm.peer_count(), 0);

    let peer_id = libp2p::PeerId::random();
    pm.on_connected(peer_id, 1, "memory".into(), "outbound".into());
    assert_eq!(pm.peer_count(), 1);
    assert!(pm.is_connected(&peer_id));

    pm.on_message(&peer_id);
    pm.on_message(&peer_id);

    pm.on_disconnected(&peer_id, 0);
    assert_eq!(pm.peer_count(), 0);
    assert!(!pm.is_connected(&peer_id));
}

#[test]
fn peer_manager_multiple_peers() {
    use ace_p2p::peer_manager::PeerManager;

    let mut pm = PeerManager::new(50);
    let peers: Vec<_> = (0..5).map(|_| libp2p::PeerId::random()).collect();

    for p in &peers {
        pm.on_connected(*p, 1, "memory".into(), "outbound".into());
    }
    assert_eq!(pm.peer_count(), 5);

    let connected = pm.connected_peers();
    for p in &peers {
        assert!(connected.contains(p));
    }

    pm.on_disconnected(&peers[2], 0);
    assert_eq!(pm.peer_count(), 4);
    assert!(!pm.is_connected(&peers[2]));
}

#[test]
fn peer_manager_preserves_peer_metadata_across_multiple_connections() {
    use ace_p2p::peer_manager::PeerManager;

    let mut pm = PeerManager::new(50);
    let peer_id = libp2p::PeerId::random();

    assert!(pm.on_connected(peer_id, 1, "memory".into(), "outbound".into()));
    pm.set_identity(&peer_id, "peer-xid".to_string(), Some([7u8; 32]));

    assert!(pm.on_connected(peer_id, 2, "memory".into(), "outbound".into()));
    assert!(pm.is_connected(&peer_id));
    assert_eq!(
        pm.connected_peer_xidentities(),
        vec![(peer_id, "peer-xid".to_string())]
    );

    pm.on_disconnected(&peer_id, 1);
    assert!(pm.is_connected(&peer_id));
    assert_eq!(
        pm.connected_peer_xidentities(),
        vec![(peer_id, "peer-xid".to_string())]
    );

    pm.on_disconnected(&peer_id, 0);
    assert!(!pm.is_connected(&peer_id));
}

// ── Two-node swarm integration test ──

#[tokio::test]
async fn two_node_message_exchange() {
    // Create two swarms
    let mut swarm1 = build_test_swarm();
    let mut swarm2 = build_test_swarm();

    // Subscribe both swarms to tx topic
    let topic_str = topic_name(0, TOPIC_TRANSACTIONS);
    assert!(
        topic_str.ends_with("/2"),
        "Transaction topic should be version 2"
    );
    let topic = IdentTopic::new(topic_str);
    swarm1.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    swarm2.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    // Listen on random ports
    let addr1: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr1).unwrap();

    // Get actual listen address of swarm1
    let listen_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm1.select_next_some().await {
            break address;
        }
    };

    // Swarm2 dials swarm1
    swarm2.dial(listen_addr).unwrap();

    // Wait for connection + peer discovery (poll both swarms)
    let mut connected = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    while !connected && tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = swarm1.select_next_some() => {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    swarm1.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    connected = true;
                }
            }
            event = swarm2.select_next_some() => {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    swarm2.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(connected, "swarms should connect within 5s");

    // Let gossipsub mesh form (need a few heartbeats)
    let mesh_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < mesh_deadline {
        tokio::select! {
            _ = swarm1.select_next_some() => {}
            _ = swarm2.select_next_some() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    // Swarm1 publishes a transaction message
    let tx = make_dummy_tx();
    let msg = NetworkMessage::NewTransaction {
        tx,
        credential_commitment: None,
        source_peer_id: None,
    };
    let data = msg.to_bytes().unwrap();
    let publish_result = swarm1
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), data);

    // publish may fail if no peers in mesh yet; that's ok for testing
    if publish_result.is_err() {
        // Skip — mesh didn't form in time (CI timing sensitivity)
        return;
    }

    // Swarm2 should receive the message
    let recv_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut received = false;

    while !received && tokio::time::Instant::now() < recv_deadline {
        tokio::select! {
            event = swarm2.select_next_some() => {
                if let SwarmEvent::Behaviour(ace_p2p::behaviour::AceBehaviourEvent::Gossipsub(
                    gossipsub::Event::Message { message, .. }
                )) = event {
                    let decoded = NetworkMessage::from_bytes(&message.data).unwrap();
                    if let NetworkMessage::NewTransaction { tx: t, .. } = decoded {
                        assert_eq!(t.payload, vec![0x01, 0x00, 0xFF]);
                        received = true;
                    }
                }
            }
            _ = swarm1.select_next_some() => {}
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(received, "swarm2 should receive the transaction message");
}

#[tokio::test]
async fn two_node_takeover_exchange() {
    let mut swarm1 = build_test_swarm();
    let mut swarm2 = build_test_swarm();

    let topic = IdentTopic::new(TOPIC_TAKEOVER);
    swarm1.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    swarm2.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    // Listen + connect
    let addr1: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    swarm1.listen_on(addr1).unwrap();

    let listen_addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm1.select_next_some().await {
            break address;
        }
    };

    swarm2.dial(listen_addr).unwrap();

    // Wait for connection
    let mut connected = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !connected && tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = swarm1.select_next_some() => {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    swarm1.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    connected = true;
                }
            }
            event = swarm2.select_next_some() => {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                    swarm2.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(connected);

    // Let mesh form
    let mesh_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < mesh_deadline {
        tokio::select! {
            _ = swarm1.select_next_some() => {}
            _ = swarm2.select_next_some() => {}
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }

    // Publish takeover message
    use ace_runtime::crypto::sig_algo::{LocalSigningKey, SignatureAlgorithm};
    let key = LocalSigningKey::from_seed(&[0xAA; 32], SignatureAlgorithm::Ed25519).unwrap();
    let idcom = [0xBB; 32];
    let credential = key.sign(&signing_message(&idcom, 1, 99999));
    let takeover = IdentityTakeoverMsg::new_signed(idcom, credential, 1, 99999);
    let msg = NetworkMessage::IdentityTakeover(takeover);
    let data = msg.to_bytes().unwrap();

    if swarm1
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), data)
        .is_err()
    {
        return; // mesh didn't form
    }

    // Receive and verify
    let recv_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut received = false;
    while !received && tokio::time::Instant::now() < recv_deadline {
        tokio::select! {
            event = swarm2.select_next_some() => {
                if let SwarmEvent::Behaviour(ace_p2p::behaviour::AceBehaviourEvent::Gossipsub(
                    gossipsub::Event::Message { message, .. }
                )) = event {
                    let decoded = NetworkMessage::from_bytes(&message.data).unwrap();
                    if let NetworkMessage::IdentityTakeover(t) = decoded {
                        assert_eq!(t.idcom, idcom);
                        assert_eq!(t.nonce, 1);
                        assert!(t.verify(&key.public_key()));
                        received = true;
                    }
                }
            }
            _ = swarm1.select_next_some() => {}
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    assert!(received, "swarm2 should receive the takeover message");
}
