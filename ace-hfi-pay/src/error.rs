//! Error types for HFIPay.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HfiPayError {
    #[error("invalid intent id")]
    InvalidIntentId,

    #[error("intent not found: {0}")]
    IntentNotFound(String),

    #[error("intent already claimed")]
    IntentAlreadyClaimed,

    #[error("intent not yet funded")]
    IntentNotFunded,

    #[error("intent not expired (current_slot={current_slot}, expiry={expiry})")]
    IntentNotExpired { current_slot: u64, expiry: u64 },

    #[error("intent has expired")]
    IntentExpired,

    #[error("invalid claim signature")]
    InvalidClaimSignature,

    #[error("blinded binding mismatch")]
    BlindedBindingMismatch,

    #[error("invalid claim proof public inputs")]
    InvalidClaimProofInputs,

    #[error("invalid claim proof")]
    InvalidClaimProof,

    #[error("invalid withdraw signature")]
    InvalidWithdrawSignature,

    #[error("invalid refund signature")]
    InvalidRefundSignature,

    #[error("intent is underfunded: have {have}, need {need}")]
    IntentUnderfunded { have: u64, need: u64 },

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    #[error("balance overflow")]
    BalanceOverflow,

    #[error("nonce overflow")]
    NonceOverflow,

    #[error("no refund destination configured")]
    NoRefundDestination,

    #[error("refund authorization missing")]
    MissingRefundAuthorization,

    #[error("refund authorizer missing")]
    MissingRefundAuthorizer,

    #[error("refund authorizer does not match actual funder")]
    RefundAuthorizerMismatch,

    #[error("claim binding missing")]
    MissingClaimBinding,

    #[error("destination account is controlled by a different authorization key")]
    DestinationAuthConflict,

    #[error("missing destination authorization material for account creation")]
    MissingDestinationAuth,

    #[error("cross-vm error: {0}")]
    CrossVmError(String),

    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("token runtime error: {0}")]
    TokenRuntimeError(String),

    #[error("invalid registration signature")]
    InvalidRegistrationSignature,

    #[error("invalid binding attestation")]
    InvalidBindingAttestation,

    #[error("quote has expired")]
    QuoteExpired,

    #[error("invalid verified-quote proof public inputs")]
    InvalidQuoteProofInputs,

    #[error("invalid verified-quote proof")]
    InvalidQuoteProof,

    #[error("recipient not registered")]
    RecipientNotRegistered,

    #[error("expiry too far in the future")]
    ExpiryTooFar,

    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },
}
