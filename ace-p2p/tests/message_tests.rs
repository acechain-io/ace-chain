use ace_p2p::messages::{
    CompactNetworkProposal, NetworkMessage, NetworkPrevote, NetworkProposal, MAX_MESSAGE_BYTES,
};
use ace_runtime::crypto::TaggedSignature;
use ace_runtime::types::block::{Block, BlockHeader};
use ace_runtime::types::transaction::Transaction;

fn make_dummy_tx() -> Transaction {
    use ace_runtime::types::attestation::{Attestation, Domain};
    Transaction {
        payload: vec![0x01, 0x00],
        attestation: Attestation {
            obj_hash: [0u8; 32],
            idcom: [1u8; 32],
            domain: Domain {
                chain_id: 1,
                slot: 0,
            },
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
        raw_chain: None,
        zk_auth: None,
    }
}

fn make_dummy_block() -> Block {
    Block {
        header: BlockHeader {
            slot: 42,
            parent_hash: [0x11; 32],
            state_root: [0x22; 32],
            tx_merkle_root: [0x33; 32],
            attest_merkle_root: [0x44; 32],
            poh_hash: [0x55; 32],
            leader_idcom: [0x66; 32],
            timestamp: 1234,
            tx_count: 0,
            round: 2,
            mev_ace_material_hash: [0u8; 32],
        },
        transactions: vec![],
        mev_ace: None,
    }
}

#[test]
fn transaction_message_roundtrip() {
    let tx = make_dummy_tx();
    let msg = NetworkMessage::NewTransaction {
        tx,
        credential_commitment: None,
        source_peer_id: None,
    };
    let bytes = msg.to_bytes().unwrap();
    let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

    match decoded {
        NetworkMessage::NewTransaction { tx: t, .. } => {
            assert_eq!(t.payload, vec![0x01, 0x00]);
        }
        _ => panic!("expected NewTransaction"),
    }
}

#[test]
fn proposal_message_roundtrip() {
    let msg = NetworkMessage::Proposal(NetworkProposal {
        height: 42,
        round: 2,
        block: make_dummy_block(),
        valid_round: Some(1),
        proposer: [1u8; 32],
        signature: TaggedSignature::default(),
        chain_id: 122766,
    });
    let bytes = msg.to_bytes().unwrap();
    let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

    match decoded {
        NetworkMessage::Proposal(p) => {
            assert_eq!(p.height, 42);
            assert_eq!(p.round, 2);
            assert_eq!(p.valid_round, Some(1));
        }
        _ => panic!("expected Proposal"),
    }
}

#[test]
fn compact_proposal_roundtrip_skips_local_peer_id() {
    let block = make_dummy_block();
    let tx = make_dummy_tx();
    let msg = NetworkMessage::CompactProposal(CompactNetworkProposal {
        height: 42,
        round: 2,
        header: block.header.clone(),
        tx_hashes: vec![tx.tx_hash()],
        tx_wire_hashes: vec![tx.wire_hash()],
        valid_round: Some(1),
        proposer: [1u8; 32],
        signature: TaggedSignature::default(),
        chain_id: 122766,
        proposer_peer_id: Some("12D3KooW-test".to_string()),
        mev_ace: None,
    });
    let bytes = msg.to_bytes().unwrap();
    let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

    match decoded {
        NetworkMessage::CompactProposal(p) => {
            assert_eq!(p.height, 42);
            assert_eq!(p.tx_hashes.len(), 1);
            assert_eq!(p.tx_wire_hashes.len(), 1);
            assert!(p.proposer_peer_id.is_none());
        }
        _ => panic!("expected CompactProposal"),
    }
}

#[test]
fn topic_mapping() {
    let tx_msg = NetworkMessage::NewTransaction {
        tx: make_dummy_tx(),
        credential_commitment: None,
        source_peer_id: None,
    };
    assert_eq!(tx_msg.topic(), "txs");

    let prevote_msg = NetworkMessage::Prevote(NetworkPrevote {
        height: 0,
        round: 0,
        block_hash: [0; 32],
        voter: [0; 32],
        voter_stake: 0,
        signature: TaggedSignature::default(),
        chain_id: 0,
    });
    assert_eq!(prevote_msg.topic(), "prevotes");
}

#[test]
fn stripped_ml_dsa_44_tx_survives_network_roundtrip() {
    // End-to-end regression guard for the AR-ACE relay path.  The stripped
    // placeholder must:
    //   1. not panic during construction;
    //   2. serialize through bincode (the gossipsub transport format);
    //   3. deserialize back into an equal transaction whose `tx_hash` matches
    //      the full-credential counterpart so mempool dedup works;
    //   4. report `is_credential_stripped() == true` on the receiving side so
    //      `ready_transactions()` can exclude it from block production.
    use ace_runtime::types::attestation::{Attestation, Domain};

    let full_tx = Transaction {
        payload: b"pqc-payload".to_vec(),
        attestation: Attestation {
            obj_hash: [0x77; 32],
            idcom: [0x88; 32],
            domain: Domain {
                chain_id: 42,
                slot: 7,
            },
            context_tag: [0x03; 16],
            credential: TaggedSignature::ml_dsa_44(vec![0xAA; 2420]),
        },
        raw_chain: None,
        zk_auth: None,
    };
    let stripped = full_tx.stripped_for_gossip();
    assert!(stripped.is_credential_stripped());
    assert_eq!(stripped.tx_hash(), full_tx.tx_hash());

    let msg = NetworkMessage::NewTransaction {
        tx: stripped.clone(),
        credential_commitment: None,
        source_peer_id: None,
    };
    let bytes = msg.to_bytes().expect("stripped NewTransaction must encode");
    let decoded = NetworkMessage::from_bytes(&bytes).expect("stripped NewTransaction must decode");

    let rx_tx = match decoded {
        NetworkMessage::NewTransaction { tx, .. } => tx,
        other => panic!("expected NewTransaction, got {:?}", other),
    };
    assert_eq!(rx_tx, stripped);
    assert!(rx_tx.is_credential_stripped());
    assert_eq!(rx_tx.tx_hash(), full_tx.tx_hash());

    // Sanity check on the bandwidth win: the 3-byte placeholder must encode
    // into a wire payload noticeably smaller than the full 2,420-byte sig.
    let full_bytes = NetworkMessage::NewTransaction {
        tx: full_tx,
        credential_commitment: None,
        source_peer_id: None,
    }
    .to_bytes()
    .expect("full tx must encode");
    assert!(
        bytes.len() + 2000 < full_bytes.len(),
        "stripped bytes ({}) should be at least ~2KB smaller than full ({})",
        bytes.len(),
        full_bytes.len()
    );
}

#[test]
fn oversized_message_is_rejected() {
    use ace_runtime::types::attestation::{Attestation, Domain};

    let tx = Transaction {
        payload: vec![0u8; MAX_MESSAGE_BYTES],
        attestation: Attestation {
            obj_hash: [0u8; 32],
            idcom: [1u8; 32],
            domain: Domain {
                chain_id: 1,
                slot: 0,
            },
            context_tag: [0u8; 16],
            credential: TaggedSignature::ed25519([0u8; 64]),
        },
        raw_chain: None,
        zk_auth: None,
    };
    let msg = NetworkMessage::NewTransaction {
        tx,
        credential_commitment: None,
        source_peer_id: None,
    };
    assert!(msg.to_bytes().is_err());
}
