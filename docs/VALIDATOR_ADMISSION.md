# Validator Admission

ACE testnet separates full node participation from validator participation.

## Full Node

A full node can:

- sync and verify blocks
- serve local JSON-RPC
- relay transactions
- relay blocks
- register as a public node
- provide archive, indexing, proof, or light-client services when configured

A full node cannot:

- vote in consensus
- produce blocks
- change transaction final ordering
- increase validator quorum
- bypass validator admission

## Validator

A validator must be admitted by the network's validator admission policy. Setting `validator: true` in a local config is not enough.

Validator admission requires the network to recognize the validator identity, consensus key, P2P peer ID, voting power, and status. During the current testnet phase, this remains permissioned.

## Candidate Preflight

Use `ace_checkValidatorCandidate` to verify whether local configuration is structurally ready for validator candidacy. This is an operator preflight, not a governance decision.

## Safe Boundary

The public full node network is designed to expand relay, RPC, archive, and discovery capacity without expanding consensus authority. Validator set changes are handled separately to preserve consensus safety.
