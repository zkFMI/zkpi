//! Public state-continuity STARK adapter, pinned to Miden VM 0.32.0.
//!
//! The fixed program checks an ordered chain of already-public state roots and
//! binds its eight padded entries, settlement flags, receipt and zkPI digests.
//! It does not verify the receipts' signatures, finality, hidden balances,
//! range/price/winner rules, or any curve-based proof. An independent source of
//! finalized records must supply the expected statement to verification.
use miden_core::Felt;
use miden_vm::{
    Assembler, DefaultHost, ExecutionClaim, ExecutionOptions, ExecutionProof, FastProcessor,
    HashFunction, Program, ProgramInfo, Prover, StackInputs, StackOutputs, Verifier, Word,
    advice::{AdviceInputs, AdviceStack},
    crypto::hash::Poseidon2,
};
use serde::{Deserialize, Serialize};

pub const BATCH_SLOTS: usize = 8;
pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const PROGRAM: &str = include_str!("batch.masm");
const SUITE: &str = "miden-0.32.0-blake3-256-public-continuity-v1";
pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRoots {
    pub securities: [u8; 32],
    pub cash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTransition {
    pub before: StateRoots,
    pub after: StateRoots,
    pub zkpi_digest: [u8; 32],
    pub receipt_digest: [u8; 32],
    pub settled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchContext {
    pub network_id: [u8; 32],
    pub deployment_id: [u8; 32],
    /// A scheduler-selected period, including periods with no settlement.
    pub period: u64,
    pub partition: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchStatement {
    pub version: u16,
    pub context: BatchContext,
    pub initial: StateRoots,
    pub final_state: StateRoots,
    pub real_entries: u8,
    pub batch_commitment: [u64; 4],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchProof {
    pub version: u16,
    pub suite: String,
    pub proof: Vec<u8>,
}

/// Opt-in offline implementation of the shared crypto boundary. Register this
/// with `zkfmi_crypto::backend::Provider::register_proof_verifier`; the crypto
/// primitive crate itself never depends on Miden or enables this implicitly.
pub struct PublicBatchVerifier;

impl zkfmi_crypto::traits::ProofVerifier for PublicBatchVerifier {
    fn suite(&self) -> zkfmi_crypto::suite::Suite {
        zkfmi_crypto::suite::Suite::new(zkfmi_crypto::suite::SuiteId::MidenPublicBatchV1)
    }

    fn verify_proof(&self, statement: &[u8], proof: &[u8]) -> zkfmi_crypto::error::Result<()> {
        use zkfmi_crypto::error::CryptoError;
        if statement.len() > 16 * 1024 || proof.len() > MAX_PROOF_BYTES * 5 {
            return Err(CryptoError::InvalidEncoding);
        }
        let expected: BatchStatement =
            serde_json::from_slice(statement).map_err(|_| CryptoError::InvalidEncoding)?;
        let envelope: BatchProof =
            serde_json::from_slice(proof).map_err(|_| CryptoError::InvalidEncoding)?;
        if expected.version != PROTOCOL_VERSION || envelope.version != PROTOCOL_VERSION {
            return Err(CryptoError::UnknownVersion);
        }
        if envelope.suite != SUITE {
            return Err(CryptoError::UnsupportedSuite);
        }
        verify(&expected, &envelope).map_err(|_| CryptoError::InvalidProof)
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn hash_bytes(domain: u32, bytes: &[u8]) -> Word {
    let mut elements = vec![Felt::from(domain), Felt::from(bytes.len() as u32)];
    for chunk in bytes.chunks(4) {
        let mut value = [0u8; 4];
        value[..chunk.len()].copy_from_slice(chunk);
        elements.push(Felt::from(u32::from_le_bytes(value)));
    }
    Poseidon2::hash_elements(&elements)
}

fn root_word(roots: &StateRoots) -> Word {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&roots.securities);
    bytes.extend_from_slice(&roots.cash);
    hash_bytes(0x52544f31, &bytes)
}

fn receipt_word(row: &PublicTransition, slot: usize, idle: bool) -> Word {
    let mut bytes = vec![u8::from(idle), slot as u8];
    bytes.extend_from_slice(&row.zkpi_digest);
    bytes.extend_from_slice(&row.receipt_digest);
    hash_bytes(0x52435031, &bytes)
}

fn context_word(statement: &BatchStatement) -> Word {
    let mut bytes = Vec::with_capacity(90);
    bytes.extend_from_slice(&statement.version.to_le_bytes());
    bytes.extend_from_slice(&statement.context.network_id);
    bytes.extend_from_slice(&statement.context.deployment_id);
    bytes.extend_from_slice(&statement.context.period.to_le_bytes());
    bytes.extend_from_slice(&statement.context.partition.to_le_bytes());
    bytes.push(statement.real_entries);
    bytes.push(BATCH_SLOTS as u8);
    hash_bytes(0x43545831, &bytes)
}

fn flag_word(settled: bool) -> Word {
    Word::from([
        Felt::from(u32::from(settled)),
        Felt::from(0u32),
        Felt::from(0u32),
        Felt::from(0u32),
    ])
}

fn row_word(row: &PublicTransition, slot: usize, idle: bool) -> Word {
    let receipt = Poseidon2::merge(&[flag_word(row.settled), receipt_word(row, slot, idle)]);
    let after = Poseidon2::merge(&[root_word(&row.after), receipt]);
    Poseidon2::merge(&[root_word(&row.before), after])
}

fn pad_rows(initial: &StateRoots, rows: &[PublicTransition]) -> Result<Vec<PublicTransition>> {
    if rows.len() > BATCH_SLOTS {
        return Err("batch exceeds eight slots".into());
    }
    let final_state = rows.last().map_or(initial, |row| &row.after).clone();
    let mut padded = rows.to_vec();
    padded.resize_with(BATCH_SLOTS, || PublicTransition {
        before: final_state.clone(),
        after: final_state.clone(),
        zkpi_digest: [0; 32],
        receipt_digest: [0; 32],
        settled: true,
    });
    Ok(padded)
}

/// Derive from independently retrieved public records, not from a proof's own
/// claimed inputs. Invalid state chains are deliberately left for the VM to
/// reject; host validation is not used as a substitute for proving the relation.
pub fn statement(
    context: BatchContext,
    initial: StateRoots,
    rows: &[PublicTransition],
) -> Result<BatchStatement> {
    let padded = pad_rows(&initial, rows)?;
    let mut result = BatchStatement {
        version: PROTOCOL_VERSION,
        context,
        initial: initial.clone(),
        final_state: rows.last().map_or(initial, |r| r.after.clone()),
        real_entries: rows.len() as u8,
        batch_commitment: [0; 4],
    };
    let mut accumulator = context_word(&result);
    for (slot, row) in padded.iter().enumerate() {
        accumulator = Poseidon2::merge(&[accumulator, row_word(row, slot, slot >= rows.len())]);
    }
    result.batch_commitment =
        std::array::from_fn(|i| accumulator.as_elements()[i].as_canonical_u64());
    Ok(result)
}

fn program() -> Result<Program> {
    Assembler::default()
        .assemble_program("qomm_public_batch_v1", PROGRAM)
        .map(|p| p.unwrap_program())
        .map_err(err)
}

fn inputs(expected: &BatchStatement) -> Result<StackInputs> {
    if expected.version != PROTOCOL_VERSION || usize::from(expected.real_entries) > BATCH_SLOTS {
        return Err("unsupported batch statement version or size".into());
    }
    let mut values = Vec::with_capacity(16);
    values.extend_from_slice(root_word(&expected.initial).as_elements());
    values.extend_from_slice(context_word(expected).as_elements());
    values.extend_from_slice(root_word(&expected.final_state).as_elements());
    for v in expected.batch_commitment {
        values.push(Felt::new(v).map_err(|_| "noncanonical batch commitment")?);
    }
    StackInputs::new(&values).map_err(err)
}

fn outputs() -> Result<StackOutputs> {
    StackOutputs::new(&[Felt::from(1u32)]).map_err(err)
}

pub fn prove(expected: &BatchStatement, rows: &[PublicTransition]) -> Result<BatchProof> {
    if usize::from(expected.real_entries) != rows.len() {
        return Err("record count mismatch".into());
    }
    let padded = pad_rows(&expected.initial, rows)?;
    let mut advice = AdviceStack::new();
    for (slot, row) in padded.iter().enumerate() {
        for word in [
            root_word(&row.before),
            root_word(&row.after),
            receipt_word(row, slot, slot >= rows.len()),
        ] {
            advice.append_elements(word.as_elements().iter().copied());
        }
        advice.append_element(Felt::from(u32::from(row.settled)));
    }
    let program = program()?;
    let witness = FastProcessor::new_with_options(
        inputs(expected)?,
        AdviceInputs::default().with_stack(advice),
        ExecutionOptions::new(Some(65536), 4096, 4096).map_err(err)?,
    )
    .map_err(err)?
    .execute_for_proving_sync(&program, &mut DefaultHost::default())
    .map_err(err)?;
    if witness.claim().stack_outputs() != &outputs()? {
        return Err("unexpected VM output".into());
    }
    let proof = Prover::new()
        .with_hash_fn(HashFunction::Blake3_256)
        .with_max_prover_memory_bytes(2 * 1024 * 1024 * 1024)
        .prove_full(witness)
        .map_err(err)?;
    let result = BatchProof {
        version: PROTOCOL_VERSION,
        suite: SUITE.into(),
        proof: proof.to_bytes(),
    };
    verify(expected, &result)?;
    Ok(result)
}

/// Expected inputs must come from the verifier's finalized-record source.
pub fn verify(expected: &BatchStatement, envelope: &BatchProof) -> Result<()> {
    if envelope.version != PROTOCOL_VERSION || envelope.suite != SUITE {
        return Err("unsupported public batch proof version or suite".into());
    }
    if envelope.proof.is_empty() || envelope.proof.len() > MAX_PROOF_BYTES {
        return Err("invalid public batch proof size".into());
    }
    let proof = ExecutionProof::read_from_bytes(&envelope.proof).map_err(err)?;
    if proof.vm().proof.hash_fn() != HashFunction::Blake3_256 {
        return Err("batch proof uses an unregistered hash function".into());
    }
    if proof.to_bytes() != envelope.proof {
        return Err("noncanonical or trailing proof bytes".into());
    }
    let claim = ExecutionClaim::from_program_info(
        ProgramInfo::from(program()?),
        inputs(expected)?,
        outputs()?,
    );
    let outcome = Verifier::new().verify(&claim, &proof).map_err(err)?;
    if !outcome.is_complete() {
        return Err("deferred proof cannot authorize an audit checkpoint".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn roots(v: u8) -> StateRoots {
        StateRoots {
            securities: [v; 32],
            cash: [v.wrapping_add(80); 32],
        }
    }
    fn context() -> BatchContext {
        BatchContext {
            network_id: [1; 32],
            deployment_id: [2; 32],
            period: 42,
            partition: 0,
        }
    }
    fn rows() -> Vec<PublicTransition> {
        (0..3)
            .map(|i| PublicTransition {
                before: roots(i),
                after: roots(i + 1),
                zkpi_digest: [i + 12; 32],
                receipt_digest: [i + 22; 32],
                settled: true,
            })
            .collect()
    }
    #[test]
    fn actual_stark_binds_public_chain_and_rejects_substitution() {
        let rows = rows();
        let expected = statement(context(), roots(0), &rows).unwrap();
        let started = std::time::Instant::now();
        let proof = prove(&expected, &rows).unwrap();
        println!(
            "P5 smoke: slots=8 real_entries=3 proof_bytes={} prove_and_verify_ms={}",
            proof.proof.len(),
            started.elapsed().as_millis()
        );
        let started = std::time::Instant::now();
        verify(&expected, &proof).unwrap();
        println!("P5 smoke: verify_ms={}", started.elapsed().as_millis());
        use zkfmi_crypto::traits::{CryptoProvider, ProofVerifier};
        let suite = PublicBatchVerifier.suite();
        let mut provider = zkfmi_crypto::backend::Provider::rustcrypto().unwrap();
        assert!(provider.proof_verifier(suite).is_err());
        provider
            .register_proof_verifier(Box::new(PublicBatchVerifier))
            .unwrap();
        assert!(
            provider
                .register_proof_verifier(Box::new(PublicBatchVerifier))
                .is_err()
        );
        let statement_wire = serde_json::to_vec(&expected).unwrap();
        let proof_wire = serde_json::to_vec(&proof).unwrap();
        provider
            .proof_verifier(suite)
            .unwrap()
            .verify_proof(&statement_wire, &proof_wire)
            .unwrap();
        assert!(
            provider
                .proof_verifier(suite)
                .unwrap()
                .verify_proof(b"{}", &proof_wire)
                .is_err()
        );
        let mut wrong = expected.clone();
        wrong.context.period += 1;
        assert!(verify(&wrong, &proof).is_err());
        wrong = expected.clone();
        wrong.final_state.cash[0] ^= 1;
        assert!(verify(&wrong, &proof).is_err());
        let mut altered = rows.clone();
        altered[1].zkpi_digest[0] ^= 1;
        assert!(verify(&statement(context(), roots(0), &altered).unwrap(), &proof).is_err());
        let mut corrupted = proof.clone();
        let middle = corrupted.proof.len() / 2;
        corrupted.proof[middle] ^= 1;
        assert!(verify(&expected, &corrupted).is_err());
        corrupted = proof.clone();
        corrupted.proof.push(0);
        assert!(verify(&expected, &corrupted).is_err());
        corrupted = proof.clone();
        corrupted.suite = "classical-only".into();
        assert!(verify(&expected, &corrupted).is_err());
    }
    #[test]
    fn vm_rejects_disconnected_chain_and_failed_settlement() {
        let mut broken = rows();
        broken[1].before = roots(99);
        let expected = statement(context(), roots(0), &broken).unwrap();
        assert!(prove(&expected, &broken).is_err());
        let mut failed = rows();
        failed[1].settled = false;
        let expected = statement(context(), roots(0), &failed).unwrap();
        assert!(prove(&expected, &failed).is_err());
    }
    #[test]
    fn empty_period_has_a_real_complete_proof() {
        let expected = statement(context(), roots(0), &[]).unwrap();
        let proof = prove(&expected, &[]).unwrap();
        verify(&expected, &proof).unwrap();
        assert_eq!(expected.initial, expected.final_state);
    }
}
