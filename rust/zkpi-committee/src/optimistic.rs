//! Shared optimistic protocol adapter using the existing node authentication.
//! The state machine is owned by the independent zkpi-optimistic crate.

use crate::application_crypto::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
pub use zkpi_optimistic::*;

/// Existing host receipt authority acknowledges canonical policy/input
/// enrollment. This is admission for computation, never settlement finality.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeExecutionAdmission {
    pub policy: OptimisticPolicy,
    pub execution: RegisteredExecution,
    pub accepted_state: Digest32,
    pub accepted_height: u64,
    pub signature: Vec<u8>,
}

impl NodeExecutionAdmission {
    fn signing_digest(&self) -> Result<Digest32, String> {
        let bytes = serde_json::to_vec(&(
            &self.policy,
            &self.execution,
            self.accepted_state,
            self.accepted_height,
        ))
        .map_err(|e| e.to_string())?;
        Ok(Sha256::new()
            .chain_update(b"zkFMI:optimistic:node-admission:v1")
            .chain_update(bytes)
            .finalize()
            .into())
    }
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, String> {
        self.signature = key.try_sign(&self.signing_digest()?)?.to_bytes();
        Ok(self)
    }
    pub fn verify(&self, trusted: Digest32, now: u64) -> Result<(), String> {
        let context = &self.execution.context;
        if self.execution.policy != self.policy.digest()?
            || self.accepted_state == [0; 32]
            || self.accepted_height == 0
            || self.execution.valid_until < now
            || context.network != self.policy.network
            || context.application != self.policy.application
            || context.verifier != self.policy.verifier
        {
            return Err("optimistic node admission is invalid or expired".into());
        }
        ApplicationAuthentication.verify(trusted, &self.signing_digest()?, &self.signature)
    }
}

impl ClaimSigner for SigningKey {
    fn identity(&self) -> Digest32 {
        self.verifying_key().to_bytes()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.try_sign(message)?.to_bytes())
    }
}

pub struct ApplicationAuthentication;

impl ClaimAuthentication for ApplicationAuthentication {
    fn verify(&self, identity: Digest32, message: &[u8], signature: &[u8]) -> Result<(), String> {
        VerifyingKey::from_bytes(&identity)
            .map_err(|e| e.to_string())?
            .verify_strict(
                message,
                &Signature::try_from(signature).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
    }
}

/// Existing complete-quote verification, executed only in a dispute. The
/// entire registered population and request are bound independently of the
/// claimed winner, so a valid proof of a different winner can reject a claim.
pub struct QuoteChallengeVerifier;

impl ChallengeVerifier for QuoteChallengeVerifier {
    fn verifier_id(&self) -> Digest32 {
        Sha256::digest(b"zkFMI:optimistic:complete-quote-verifier:v1").into()
    }

    fn verify(&self, context: &ExecutionContext, proof: &[u8]) -> Result<Digest32, String> {
        let bundle = crate::proof_codec::decode_quote_verification(proof)?;
        if context.verifier != self.verifier_id()
            || quote_input_root(
                &bundle.public,
                bundle.context,
                bundle.eligibility_bits,
                bundle.span_bits,
            )? != context.input_root
        {
            return Err("quote challenge evidence is for another admitted input".into());
        }
        bundle.verify()?;
        Ok(quote_output_root(
            bundle.proof.winner_index,
            bundle.proof.winner_value,
        ))
    }
}

pub fn quote_input_root(
    public: &zkpi_proofs::quote_proof::Public,
    transcript_context: Digest32,
    eligibility_bits: usize,
    span_bits: usize,
) -> Result<Digest32, String> {
    let registry = public
        .registry
        .iter()
        .enumerate()
        .map(|(index, policy)| zkpi_proofs::quote_proof::registered_policy_digest(index, policy))
        .collect::<Vec<_>>();
    let raw = serde_json::to_vec(&serde_json::json!({
        "transcript": transcript_context,
        "eligibility_bits": eligibility_bits, "span_bits": span_bits,
        "quantity": public.qty_commitment.compress().to_bytes(),
        "now": public.now, "sentinel": public.sentinel, "slots": public.n_slots,
        "direction": public.direction, "asset": public.asset, "reference": public.reference_price,
        "registry": registry, "registry_digest": public.registry_digest,
        "market": public.market_digest, "slot": public.slot,
    }))
    .map_err(|e| e.to_string())?;
    Ok(Sha256::new()
        .chain_update(b"zkFMI:optimistic:quote-input:v1")
        .chain_update(raw)
        .finalize()
        .into())
}

pub fn quote_output_root(winner_index: usize, winner_value: u64) -> Digest32 {
    Sha256::new()
        .chain_update(b"zkFMI:optimistic:quote-output:v1")
        .chain_update((winner_index as u64).to_be_bytes())
        .chain_update(winner_value.to_be_bytes())
        .finalize()
        .into()
}
