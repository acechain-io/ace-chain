#![cfg(feature = "test-utils")]

//! Finality state machine tests (Algorithm 2) and timeout protocol tests.

use ace_runtime::consensus::finality::{FinalityAction, FinalityEvent, FinalityStateMachine};
use ace_runtime::consensus::timeout::{TimeoutPhase, TimeoutProtocol, WitnessAvailability};
use ace_runtime::crypto::proof::{AlwaysInvalidProver, MockProver};
use ace_runtime::types::finality::{
    FinalityCertificate, FinalityProofMode, FinalityState, ZkProof,
};

/// Helper: create a well-formed finality certificate with a valid mock proof.
fn make_fc(slot: u64) -> FinalityCertificate {
    MockProver::create_mock_fc([1u8; 32], slot, [2u8; 32])
}

// ---------------------------------------------------------------------------
// Finality state machine tests
// ---------------------------------------------------------------------------

#[test]
fn test_initial_state_pending() {
    let fsm = FinalityStateMachine::new(100);
    assert_eq!(fsm.state(), FinalityState::Pending);
    assert_eq!(fsm.slot(), 100);
    assert!(!fsm.is_builder_slashed());
}

#[test]
fn test_block_received_to_soft() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Below quorum: stay Pending
    let action = fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 1,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Pending);
    assert_eq!(action, FinalityAction::None);

    // At quorum: transition to Soft
    let action = fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 2,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);
    assert_eq!(action, FinalityAction::None);
}

#[test]
fn test_valid_fc_soft_to_hard() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Move to Soft
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);

    // Valid FC → Hard
    let action = fsm.on_event(
        FinalityEvent::FinalityCertReceived {
            certificate: make_fc(100),
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Hard);
    assert_eq!(action, FinalityAction::None);
}

#[test]
fn test_valid_fc_backup_to_hard() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Move to Soft
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );

    // Builder timeout → BackupWait
    fsm.on_event(FinalityEvent::BuilderTimeout, &prover);
    assert_eq!(fsm.state(), FinalityState::BackupWait);

    // Valid FC from backup prover → Hard
    let action = fsm.on_event(
        FinalityEvent::FinalityCertReceived {
            certificate: make_fc(100),
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Hard);
    assert_eq!(action, FinalityAction::None);
}

#[test]
fn test_invalid_fc_soft_to_rolledback() {
    let mut fsm = FinalityStateMachine::new(100);
    let invalid_prover = AlwaysInvalidProver;
    let mock_prover = MockProver::new();

    // Move to Soft (using mock prover for block received event)
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &mock_prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);

    // Invalid FC in Soft → deferred (anti-griefing: stays Soft, no slash)
    let action = fsm.on_event(
        FinalityEvent::FinalityCertReceived {
            certificate: make_fc(100),
        },
        &invalid_prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);
    assert_eq!(action, FinalityAction::None);
    assert!(!fsm.is_builder_slashed());

    // Builder timeout eventually moves Soft → BackupWait + slash
    let action = fsm.on_event(FinalityEvent::BuilderTimeout, &mock_prover);
    assert_eq!(fsm.state(), FinalityState::BackupWait);
    assert_eq!(action, FinalityAction::SlashBuilder);
    assert!(fsm.is_builder_slashed());
}

#[test]
fn test_invalid_fc_backup_ignored() {
    let mut fsm = FinalityStateMachine::new(100);
    let mock_prover = MockProver::new();
    let invalid_prover = AlwaysInvalidProver;

    // Move to Soft → BackupWait
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &mock_prover,
    );
    fsm.on_event(FinalityEvent::BuilderTimeout, &mock_prover);
    assert_eq!(fsm.state(), FinalityState::BackupWait);

    // Invalid FC in BackupWait → ignored (stay in BackupWait)
    let action = fsm.on_event(
        FinalityEvent::FinalityCertReceived {
            certificate: make_fc(100),
        },
        &invalid_prover,
    );
    assert_eq!(fsm.state(), FinalityState::BackupWait);
    assert_eq!(action, FinalityAction::None);
}

#[test]
fn test_builder_timeout_to_backup() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Move to Soft
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );

    // Builder timeout → BackupWait + slash
    let action = fsm.on_event(FinalityEvent::BuilderTimeout, &prover);
    assert_eq!(fsm.state(), FinalityState::BackupWait);
    assert_eq!(action, FinalityAction::SlashBuilder);
    assert!(fsm.is_builder_slashed());
}

#[test]
fn test_backup_timeout_to_rolledback() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Move to Soft → BackupWait
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );
    fsm.on_event(FinalityEvent::BuilderTimeout, &prover);
    assert_eq!(fsm.state(), FinalityState::BackupWait);

    // Backup timeout → RolledBack + requeue
    let action = fsm.on_event(FinalityEvent::BackupTimeout, &prover);
    assert_eq!(fsm.state(), FinalityState::RolledBack);
    assert_eq!(action, FinalityAction::RequeueTxs);
}

#[test]
fn test_no_double_slash() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Move to Soft
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );

    // First timeout → slash
    let action1 = fsm.on_event(FinalityEvent::BuilderTimeout, &prover);
    assert_eq!(action1, FinalityAction::SlashBuilder);
    assert!(fsm.is_builder_slashed());

    // Builder is already slashed; further events should not slash again
    // (BackupTimeout produces Requeue, not Slash)
    let action2 = fsm.on_event(FinalityEvent::BackupTimeout, &prover);
    assert_eq!(action2, FinalityAction::RequeueTxs);
}

#[test]
fn test_terminal_state_ignores_events() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Move to Hard (terminal)
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );
    fsm.on_event(
        FinalityEvent::FinalityCertReceived {
            certificate: make_fc(100),
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Hard);

    // All further events should be ignored
    let action = fsm.on_event(FinalityEvent::BuilderTimeout, &prover);
    assert_eq!(action, FinalityAction::None);
    assert_eq!(fsm.state(), FinalityState::Hard);
}

#[test]
fn test_pending_ignores_timeout() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Timeout in Pending state should be ignored
    let action = fsm.on_event(FinalityEvent::BuilderTimeout, &prover);
    assert_eq!(action, FinalityAction::None);
    assert_eq!(fsm.state(), FinalityState::Pending);
}

#[test]
fn test_fc_wrong_slot_rejected() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Move to Soft
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);

    // FC with wrong slot (999 instead of 100) → treated as invalid → deferred (anti-griefing)
    let wrong_slot_fc = FinalityCertificate {
        block_hash: [1u8; 32], // correct block_hash
        slot: 999,             // WRONG slot
        proof: ZkProof::from_bytes(vec![0u8; 256]),
        id_com_commitment: [2u8; 32],
        proof_mode: FinalityProofMode::StarkV1,
        statement_root: [0u8; 32],
        tx_count: 0,
    };
    let action = fsm.on_event(
        FinalityEvent::FinalityCertReceived {
            certificate: wrong_slot_fc,
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);
    assert_eq!(action, FinalityAction::None);
}

#[test]
fn test_fc_wrong_block_hash_rejected() {
    let mut fsm = FinalityStateMachine::new(100);
    let prover = MockProver::new();

    // Move to Soft
    fsm.on_event(
        FinalityEvent::BlockReceived {
            votes: 3,
            total_stake: 3,
            block_hash: [1u8; 32],
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);

    // FC with wrong block_hash → treated as invalid → deferred (anti-griefing)
    let wrong_hash_fc = FinalityCertificate {
        block_hash: [99u8; 32], // WRONG block hash
        slot: 100,              // correct slot
        proof: ZkProof::from_bytes(vec![0u8; 256]),
        id_com_commitment: [2u8; 32],
        proof_mode: FinalityProofMode::StarkV1,
        statement_root: [0u8; 32],
        tx_count: 0,
    };
    let action = fsm.on_event(
        FinalityEvent::FinalityCertReceived {
            certificate: wrong_hash_fc,
        },
        &prover,
    );
    assert_eq!(fsm.state(), FinalityState::Soft);
    assert_eq!(action, FinalityAction::None);
}

// ---------------------------------------------------------------------------
// Timeout protocol tests
// ---------------------------------------------------------------------------

#[test]
fn test_timeout_phases() {
    let tp = TimeoutProtocol::new(100);

    // Within builder window
    assert_eq!(tp.phase(100), TimeoutPhase::BuilderWindow);
    assert_eq!(tp.phase(101), TimeoutPhase::BuilderWindow);
    assert_eq!(tp.phase(103), TimeoutPhase::BuilderWindow);

    // Backup window (K=3, so slot 104..106)
    assert_eq!(tp.phase(104), TimeoutPhase::BackupWindow);
    assert_eq!(tp.phase(106), TimeoutPhase::BackupWindow);

    // Expired (slot > 106)
    assert_eq!(tp.phase(107), TimeoutPhase::Expired);
    assert_eq!(tp.phase(200), TimeoutPhase::Expired);
}

#[test]
fn test_timeout_resolved() {
    let mut tp = TimeoutProtocol::new(100);
    tp.resolve();

    assert_eq!(tp.phase(100), TimeoutPhase::Resolved);
    assert_eq!(tp.phase(200), TimeoutPhase::Resolved);
}

#[test]
fn test_timeout_deadlines() {
    use ace_runtime::config::{
        BUILDER_TIMEOUT_MS, K_BACKUP_SLOTS, K_BUILDER_SLOTS, TOTAL_TIMEOUT_MS,
    };
    let tp = TimeoutProtocol::new(100);
    assert_eq!(tp.builder_deadline(), 100 + K_BUILDER_SLOTS);
    assert_eq!(tp.backup_deadline(), 100 + K_BUILDER_SLOTS + K_BACKUP_SLOTS);
    assert_eq!(tp.builder_deadline_ms(), BUILDER_TIMEOUT_MS);
    assert_eq!(tp.total_deadline_ms(), TOTAL_TIMEOUT_MS);
}

#[test]
fn test_timeout_expiry_checks() {
    let tp = TimeoutProtocol::new(100);

    assert!(!tp.is_builder_expired(100));
    assert!(!tp.is_builder_expired(103));
    assert!(tp.is_builder_expired(104));

    assert!(!tp.is_fully_expired(106));
    assert!(tp.is_fully_expired(107));
}

// ---------------------------------------------------------------------------
// Witness availability tests
// ---------------------------------------------------------------------------

#[test]
fn test_witness_availability_quorum() {
    let mut wa = WitnessAvailability::new(9);

    // Need ⅔ of 9 = 6
    for i in 0..5u64 {
        wa.record_receipt(i);
        assert!(!wa.is_available());
    }

    wa.record_receipt(5); // 6th receipt
    assert!(wa.is_available());
}

#[test]
fn test_witness_availability_fraction() {
    let mut wa = WitnessAvailability::new(100);
    for i in 0..50u64 {
        wa.record_receipt(i);
    }
    let frac = wa.availability_fraction();
    assert!((frac - 0.5).abs() < 1e-10);
}

#[test]
fn test_witness_availability_zero_validators() {
    let wa = WitnessAvailability::new(0);
    assert_eq!(wa.availability_fraction(), 0.0);
}

#[test]
fn test_witness_availability_dedup() {
    let mut wa = WitnessAvailability::new(9);

    // Same validator reports 100 times — should count as 1
    for _ in 0..100 {
        wa.record_receipt(42);
    }
    assert_eq!(wa.received_count(), 1);
    assert!(
        !wa.is_available(),
        "duplicate receipts must not inflate quorum"
    );

    // Add 5 more unique validators (total 6) → ⅔ of 9
    for i in 0..5u64 {
        wa.record_receipt(i);
    }
    assert_eq!(wa.received_count(), 6);
    assert!(wa.is_available());
}

#[test]
fn test_witness_availability_membership_check() {
    use std::collections::HashMap;

    // Validator set: IDs {0, 1, 2, 3, 4, 5, 6, 7, 8} each with stake 1
    let valid_set: HashMap<u64, u64> = (0..9).map(|id| (id, 1u64)).collect();
    let mut wa = WitnessAvailability::new_with_validator_set(9, valid_set);

    // Valid IDs should be accepted
    assert!(wa.record_receipt(0));
    assert!(wa.record_receipt(1));
    assert_eq!(wa.received_count(), 2);

    // Non-member IDs should be rejected
    assert!(!wa.record_receipt(100), "non-member ID must be rejected");
    assert!(!wa.record_receipt(999), "non-member ID must be rejected");
    assert_eq!(
        wa.received_count(),
        2,
        "rejected IDs must not inflate count"
    );

    // Fill to quorum with valid IDs (need ⅔ of 9 = 6)
    for i in 2..6u64 {
        wa.record_receipt(i);
    }
    assert_eq!(wa.received_count(), 6);
    assert!(wa.is_available());
}

#[test]
fn test_witness_availability_without_membership_accepts_all() {
    // Without validator set, any ID is accepted (backward compatible)
    let mut wa = WitnessAvailability::new(3);
    assert!(wa.record_receipt(999999));
    assert!(wa.record_receipt(0));
    assert_eq!(wa.received_count(), 2);
    assert!(wa.is_available()); // 2/3 = ⅔ quorum
}
