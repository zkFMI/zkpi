//! Development checks for the shared state machine with real hybrid keys.
//! The small hash relation exercises the verifier interface; it is not a
//! QOMM/OCLOB settlement acceptance run or a performance benchmark.
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zkpi_committee::application_crypto::SigningKey;
use zkpi_committee::optimistic::*;

struct HashRelation;
impl ChallengeVerifier for HashRelation {
    fn verifier_id(&self) -> Digest32 { [3; 32] }
    fn verify(&self, context: &ExecutionContext, proof: &[u8]) -> Result<Digest32, String> {
        let input: Digest32 = Sha256::digest(proof).into();
        if input != context.input_root { return Err("proof is for another input".into()); }
        Ok(Sha256::new().chain_update(b"output").chain_update(proof).finalize().into())
    }
}

fn setup() -> (OptimisticState, OptimisticPolicy, SigningKey, SigningKey, ExecutionContext, Digest32) {
    let proposer = SigningKey::generate(&mut OsRng);
    let challenger = SigningKey::generate(&mut OsRng);
    let policy = OptimisticPolicy {
        network: [1; 32], application: [2; 32], verifier: [3; 32],
        proposer: proposer.identity(), bond_asset: [4; 32], proposer_bond: 100,
        challenger_bond: 10, challenge_window_seconds: 10, response_window_seconds: 5,
    };
    let context = ExecutionContext {
        network: policy.network, application: policy.application, verifier: policy.verifier,
        job: [5; 32], input_root: Sha256::digest(b"actual fixture input").into(), before_state: [6; 32],
    };
    let output = HashRelation.verify(&context, b"actual fixture input").unwrap();
    let mut state = OptimisticState::default();
    state.enroll_policy(policy.clone()).unwrap();
    state.register_execution(RegisteredExecution {
        policy: policy.digest().unwrap(), context: context.clone(), valid_until: 100,
    }).unwrap();
    state.credit_escrow(policy.bond_asset, proposer.identity(), 200).unwrap();
    state.credit_escrow(policy.bond_asset, challenger.identity(), 20).unwrap();
    (state, policy, proposer, challenger, context, output)
}

#[test]
fn no_challenge_keeps_bond_locked_until_window_and_survives_snapshot() {
    let (mut state, policy, proposer, _, context, output) = setup();
    let proposal = Proposal::signed(&policy, context.clone(), output, 11, &proposer).unwrap();
    let id = state.propose(proposal.clone(), 10, &ApplicationAuthentication).unwrap();
    assert!(state.propose(proposal, 10, &ApplicationAuthentication).is_err());
    assert_eq!(state.bond(policy.bond_asset, proposer.identity()).locked, 100);
    assert!(state.withdraw_escrow(policy.bond_asset, proposer.identity(), 101).is_err());
    assert!(state.require_finalized(id, &context, output).is_err());
    assert!(state.advance(id, 19).is_err());
    let bytes = serde_json::to_vec(&state).unwrap();
    let mut recovered: OptimisticState = serde_json::from_slice(&bytes).unwrap();
    recovered.validate(&ApplicationAuthentication).unwrap();
    recovered.advance(id, 20).unwrap();
    recovered.require_finalized(id, &context, output).unwrap();
    assert_eq!(recovered.bond(policy.bond_asset, proposer.identity()).available, 200);
    assert!(recovered.advance(id, 20).is_err());
    recovered.validate(&ApplicationAuthentication).unwrap();
}

#[test]
fn correct_defense_waits_original_window_and_forfeits_challenger_bond_once() {
    let (mut state, policy, proposer, challenger, context, output) = setup();
    let proposal = Proposal::signed(&policy, context.clone(), output, 10, &proposer).unwrap();
    let id = state.propose(proposal, 10, &ApplicationAuthentication).unwrap();
    state.challenge(Challenge::signed(id, &challenger).unwrap(), 11, &ApplicationAuthentication).unwrap();
    let before = serde_json::to_vec(&state).unwrap();
    assert!(state.answer(id, b"another input", &HashRelation, 12).is_err());
    assert_eq!(before, serde_json::to_vec(&state).unwrap());
    state.answer(id, b"actual fixture input", &HashRelation, 12).unwrap();
    assert!(state.require_finalized(id, &context, output).is_err());
    assert!(state.advance(id, 19).is_err());
    state.advance(id, 20).unwrap();
    state.require_finalized(id, &context, output).unwrap();
    assert_eq!(state.bond(policy.bond_asset, proposer.identity()).available, 210);
    assert_eq!(state.bond(policy.bond_asset, challenger.identity()).available, 10);
    assert!(state.answer(id, b"actual fixture input", &HashRelation, 20).is_err());
    state.validate(&ApplicationAuthentication).unwrap();
}

#[test]
fn proven_wrong_result_and_timeout_reject_and_transfer_collateral() {
    for timeout in [false, true] {
        let (mut state, policy, proposer, challenger, context, _) = setup();
        let proposal = Proposal::signed(&policy, context.clone(), [99; 32], 10, &proposer).unwrap();
        let id = state.propose(proposal, 10, &ApplicationAuthentication).unwrap();
        // A challenge near the end gets its full response window.
        state.challenge(Challenge::signed(id, &challenger).unwrap(), 19, &ApplicationAuthentication).unwrap();
        assert!(state.advance(id, 20).is_err());
        if timeout {
            assert!(state.advance(id, 23).is_err());
            assert!(state.answer(id, b"actual fixture input", &HashRelation, 24).is_err());
            state.advance(id, 24).unwrap();
        } else {
            state.answer(id, b"actual fixture input", &HashRelation, 20).unwrap();
        }
        assert!(state.require_finalized(id, &context, [99; 32]).is_err());
        assert!(matches!(state.claim(&id).unwrap().status, ClaimStatus::Rejected { .. }));
        assert_eq!(state.bond(policy.bond_asset, proposer.identity()).available, 100);
        assert_eq!(state.bond(policy.bond_asset, challenger.identity()).available, 120);
        assert!(state.advance(id, 100).is_err());
        state.validate(&ApplicationAuthentication).unwrap();
    }
}

#[test]
fn signatures_enrollment_scope_and_collateral_fail_closed() {
    let (mut state, policy, proposer, challenger, context, output) = setup();
    let original = Proposal::signed(&policy, context.clone(), output, 10, &proposer).unwrap();
    for mutate in 0..4 {
        let mut proposal = original.clone();
        match mutate {
            0 => proposal.output_root[0] ^= 1,
            1 => proposal.context.application[0] ^= 1,
            2 => proposal.signature[20] ^= 1,
            _ => proposal.policy[0] ^= 1,
        }
        assert!(state.propose(proposal, 10, &ApplicationAuthentication).is_err());
    }
    assert!(state.propose(original.clone(), 11, &ApplicationAuthentication).is_err());
    let id = state.propose(original, 10, &ApplicationAuthentication).unwrap();
    assert!(state.challenge(Challenge::signed(id, &proposer).unwrap(), 11, &ApplicationAuthentication).is_err());
    let mut altered = Challenge::signed(id, &challenger).unwrap();
    altered.claim[0] ^= 1;
    assert!(state.challenge(altered, 11, &ApplicationAuthentication).is_err());
    assert!(state.challenge(Challenge::signed(id, &challenger).unwrap(), 20, &ApplicationAuthentication).is_err());
    let unfunded = SigningKey::generate(&mut OsRng);
    assert!(state.challenge(Challenge::signed(id, &unfunded).unwrap(), 11, &ApplicationAuthentication).is_err());
    let mut changed = context;
    changed.input_root[0] ^= 1;
    let duplicate_job = Proposal::signed(&policy, changed, output, 10, &proposer).unwrap();
    assert!(state.propose(duplicate_job, 10, &ApplicationAuthentication).is_err());
    state.validate(&ApplicationAuthentication).unwrap();
}

#[test]
fn snapshot_cannot_drop_locked_bonds_or_change_claim_binding() {
    let (mut state, policy, proposer, _, context, output) = setup();
    let id = state.propose(Proposal::signed(&policy, context, output, 10, &proposer).unwrap(), 10, &ApplicationAuthentication).unwrap();
    for change_bond in [false, true] {
        let mut json = serde_json::to_value(&state).unwrap();
        if change_bond {
            json["bonds"][format!("{}:{}", hex::encode(policy.bond_asset), hex::encode(proposer.identity()))]["locked"] = 0.into();
        } else {
            json["claims"][hex::encode(id)]["proposal"]["output_root"][0] = 77.into();
        }
        let restored: OptimisticState = serde_json::from_value(json).unwrap();
        assert!(restored.validate(&ApplicationAuthentication).is_err());
    }
}
