//! Explicit quote authorization variants. Authentication of an optimistic
//! proposal is NOT finality: the canonical host must call `require_finalized`
//! before moving any assets. Full joint-proof wire bytes remain unchanged.

use crate::optimistic::{
    quote_input_root, quote_output_root, ApplicationAuthentication, ChallengeVerifier,
    OptimisticPolicy, OptimisticState, Proposal, QuoteChallengeVerifier,
};
use crate::proof_codec::{
    decode_quote_verification, encode_quote_verification, QuoteVerificationBundle,
};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use serde::{Deserialize, Serialize};
use zkpi_proofs::quote_proof::{Public, RegisteredPolicy};

const MAGIC: &[u8] = b"zkFMI:optimistic-quote:v1\0";

#[derive(Debug)]
pub enum QuoteAuthorization {
    JointProof(QuoteVerificationBundle),
    Optimistic(OptimisticQuote),
}

#[derive(Debug)]
pub struct OptimisticQuote {
    pub context: [u8; 32],
    pub eligibility_bits: usize,
    pub span_bits: usize,
    pub public: Public,
    pub winner_index: usize,
    pub winner_value: u64,
    pub policy: OptimisticPolicy,
    pub proposal: Proposal,
}

impl From<QuoteVerificationBundle> for QuoteAuthorization {
    fn from(value: QuoteVerificationBundle) -> Self {
        Self::JointProof(value)
    }
}

impl QuoteAuthorization {
    pub fn public(&self) -> &Public {
        match self {
            Self::JointProof(q) => &q.public,
            Self::Optimistic(q) => &q.public,
        }
    }
    pub fn context(&self) -> [u8; 32] {
        match self {
            Self::JointProof(q) => q.context,
            Self::Optimistic(q) => q.context,
        }
    }
    pub fn eligibility_bits(&self) -> usize {
        match self {
            Self::JointProof(q) => q.eligibility_bits,
            Self::Optimistic(q) => q.eligibility_bits,
        }
    }
    pub fn span_bits(&self) -> usize {
        match self {
            Self::JointProof(q) => q.span_bits,
            Self::Optimistic(q) => q.span_bits,
        }
    }
    pub fn winner_index(&self) -> usize {
        match self {
            Self::JointProof(q) => q.proof.winner_index,
            Self::Optimistic(q) => q.winner_index,
        }
    }

    /// Verifies evidence authentication. Optimistic evidence still needs the
    /// separate canonical-state finalization gate at settlement.
    pub fn verify(&self) -> Result<[u8; 32], String> {
        match self {
            Self::JointProof(q) => q.verify(),
            Self::Optimistic(q) => {
                if q.public.registry.is_empty()
                    || q.public.registry.len() > crate::proof_codec::MAX_QUOTE_MAKERS
                    || q.winner_index >= q.public.registry.len()
                    || q.proposal.context.verifier != QuoteChallengeVerifier.verifier_id()
                    || q.proposal.context.input_root
                        != quote_input_root(&q.public, q.context, q.eligibility_bits, q.span_bits)?
                    || q.proposal.output_root != quote_output_root(q.winner_index, q.winner_value)
                {
                    return Err(
                        "optimistic quote does not match its signed complete input and output"
                            .into(),
                    );
                }
                q.proposal
                    .verify(&q.policy, 0, &ApplicationAuthentication)?;
                q.proposal.id()
            }
        }
    }

    pub fn require_finalized(&self, state: &OptimisticState) -> Result<(), String> {
        self.verify()?;
        if let Self::Optimistic(q) = self {
            state.require_finalized(
                q.proposal.id()?,
                &q.proposal.context,
                q.proposal.output_root,
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    context: [u8; 32],
    eligibility_bits: usize,
    span_bits: usize,
    qty: [u8; 32],
    now: i64,
    sentinel: i64,
    n_slots: i64,
    direction: u8,
    asset: u32,
    reference_price: i64,
    registry_digest: [u8; 32],
    market_digest: [u8; 32],
    slot: u64,
    registry: Vec<(u32, [[u8; 32]; 9])>,
    winner_index: usize,
    winner_value: u64,
    policy: OptimisticPolicy,
    proposal: Proposal,
}

pub fn encode_quote_authorization(value: &QuoteAuthorization) -> Result<Vec<u8>, String> {
    value.verify()?;
    let q = match value {
        QuoteAuthorization::JointProof(q) => return encode_quote_verification(q),
        QuoteAuthorization::Optimistic(q) => q,
    };
    let p = &q.public;
    let wire = Wire {
        context: q.context,
        eligibility_bits: q.eligibility_bits,
        span_bits: q.span_bits,
        qty: p.qty_commitment.compress().to_bytes(),
        now: p.now,
        sentinel: p.sentinel,
        n_slots: p.n_slots,
        direction: p.direction,
        asset: p.asset,
        reference_price: p.reference_price,
        registry_digest: p.registry_digest,
        market_digest: p.market_digest,
        slot: p.slot,
        registry: p
            .registry
            .iter()
            .map(|r| {
                (
                    r.maker_asset,
                    [
                        r.ask_level,
                        r.spread,
                        r.slope,
                        r.invcoef,
                        r.inv,
                        r.maxqty,
                        r.expiry,
                        r.active,
                        r.use_ref,
                    ]
                    .map(|p| p.compress().to_bytes()),
                )
            })
            .collect(),
        winner_index: q.winner_index,
        winner_value: q.winner_value,
        policy: q.policy.clone(),
        proposal: q.proposal.clone(),
    };
    let mut raw = MAGIC.to_vec();
    raw.extend(serde_json::to_vec(&wire).map_err(|e| e.to_string())?);
    Ok(raw)
}

pub fn decode_quote_authorization(raw: &[u8]) -> Result<QuoteAuthorization, String> {
    if !raw.starts_with(MAGIC) {
        return decode_quote_verification(raw).map(Into::into);
    }
    if raw.len() > 1024 * 1024 {
        return Err("optimistic quote exceeds its wire bound".into());
    }
    let w: Wire = serde_json::from_slice(&raw[MAGIC.len()..]).map_err(|e| e.to_string())?;
    let point = |raw| {
        CompressedRistretto(raw)
            .decompress()
            .ok_or_else(|| "optimistic quote contains an invalid commitment".to_string())
    };
    let registry = w
        .registry
        .into_iter()
        .map(|(maker_asset, raw)| {
            let p = raw
                .into_iter()
                .map(point)
                .collect::<Result<Vec<RistrettoPoint>, String>>()?;
            Ok(RegisteredPolicy {
                maker_asset,
                ask_level: p[0],
                spread: p[1],
                slope: p[2],
                invcoef: p[3],
                inv: p[4],
                maxqty: p[5],
                expiry: p[6],
                active: p[7],
                use_ref: p[8],
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let q = QuoteAuthorization::Optimistic(OptimisticQuote {
        context: w.context,
        eligibility_bits: w.eligibility_bits,
        span_bits: w.span_bits,
        public: Public {
            qty_commitment: point(w.qty)?,
            now: w.now,
            sentinel: w.sentinel,
            n_slots: w.n_slots,
            direction: w.direction,
            asset: w.asset,
            reference_price: w.reference_price,
            registry_digest: w.registry_digest,
            market_digest: w.market_digest,
            slot: w.slot,
            registry,
        },
        winner_index: w.winner_index,
        winner_value: w.winner_value,
        policy: w.policy,
        proposal: w.proposal,
    });
    q.verify()?;
    Ok(q)
}
