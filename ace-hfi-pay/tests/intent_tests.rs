use ace_hfi_pay::intent::{ChainId, Intent, IntentStatus};
use ace_model::account::AccountId;

fn make_intent() -> Intent {
    Intent::new(
        [1u8; 32],
        [0u8; 32],
        1000,
        ChainId::Native,
        AccountId::from_bytes([2u8; 32]),
        None, // mint (native balance)
        0,    // binding epoch
        Some(AccountId::from_bytes([3u8; 32])),
        Some(AccountId::from_bytes([4u8; 32])),
        None,
        100, // expiry slot
        10,  // created_at
    )
}

#[test]
fn intent_starts_as_created() {
    let intent = make_intent();
    assert_eq!(intent.status, IntentStatus::Created);
    assert!(intent.owner.is_none());
    assert!(intent.claim_pubkey.is_none());
    assert!(intent.refund_auth.is_none());
    assert_eq!(
        intent.refund_authorizer,
        Some(AccountId::from_bytes([4u8; 32]))
    );
    assert_eq!(intent.withdraw_nonce, 0);
}

#[test]
fn valid_transitions() {
    let mut intent = make_intent();
    assert!(intent.transition(IntentStatus::Funded).is_ok());
    assert_eq!(intent.status, IntentStatus::Funded);

    // Funded → Claimed
    let mut claimed = make_intent();
    claimed.transition(IntentStatus::Funded).unwrap();
    assert!(claimed.transition(IntentStatus::Claimed).is_ok());

    // Funded → Expired
    let mut expired = make_intent();
    expired.transition(IntentStatus::Funded).unwrap();
    assert!(expired.transition(IntentStatus::Expired).is_ok());

    // Expired → Refunded
    assert!(expired.transition(IntentStatus::Refunded).is_ok());
}

#[test]
fn invalid_transitions_rejected() {
    let mut intent = make_intent();

    // Created → Claimed (skip Funded)
    assert!(intent.transition(IntentStatus::Claimed).is_err());
    // Created → Expired
    assert!(intent.transition(IntentStatus::Expired).is_err());
    // Created → Refunded
    assert!(intent.transition(IntentStatus::Refunded).is_err());

    // Funded → Refunded (skip Expired)
    intent.transition(IntentStatus::Funded).unwrap();
    assert!(intent.transition(IntentStatus::Refunded).is_err());
}

#[test]
fn chain_id_roundtrip() {
    for chain in [
        ChainId::Native,
        ChainId::Evm,
        ChainId::Svm,
        ChainId::Bvm,
        ChainId::Tvm,
    ] {
        assert_eq!(ChainId::from_tag(chain.tag()), Some(chain));
    }
    assert_eq!(ChainId::from_tag(255), None);
}
