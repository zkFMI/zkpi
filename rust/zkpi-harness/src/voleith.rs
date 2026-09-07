//! Prime-field VOLE-in-the-Head used by the `run_voleith` measurement port.
//!
//! element-wise Mersenne-field arithmetic; the transcript and proof are the
//! same, while the implementation-dependent timing is intentionally allowed to
//! differ by the harness acceptance rule.

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

pub const P: u128 = (1u128 << 127) - 1;
pub const DEFAULT_DEPTH: usize = 8;
pub const DEFAULT_REPEATS: usize = 16;
pub const SEED_BYTES: usize = 16;
pub const COMMIT_BYTES: usize = 32;
const DOMAIN: &[u8] = b"qomm:voleith:v1";
const STATISTICAL_BITS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinearProofMetadata {
    pub name: &'static str,
    pub publicly_verifiable: bool,
    pub post_quantum: bool,
}

pub const LINEAR_PROOF_SCHEMES: [LinearProofMetadata; 2] = [
    LinearProofMetadata {
        name: "pedersen",
        publicly_verifiable: true,
        post_quantum: false,
    },
    LinearProofMetadata {
        name: "voleith",
        publicly_verifiable: true,
        post_quantum: true,
    },
];

pub fn linear_proof_metadata(name: &str) -> Result<LinearProofMetadata, String> {
    LINEAR_PROOF_SCHEMES
        .iter()
        .copied()
        .find(|scheme| scheme.name == name)
        .ok_or_else(|| {
            format!("unknown linear-proof scheme {name}; choose from ['pedersen', 'voleith']")
        })
}

#[derive(Clone)]
pub struct Packing {
    pub length: usize,
    pub depth: usize,
}

impl Packing {
    pub const fn value_bits(&self) -> usize {
        127 + STATISTICAL_BITS
    }

    pub fn slot_bits(&self) -> usize {
        self.value_bits() + 2 * self.depth + 1
    }

    pub fn slot_bytes(&self) -> usize {
        self.slot_bits().div_ceil(8)
    }

    pub fn blob_bytes(&self) -> usize {
        self.length * self.slot_bytes()
    }

    pub fn leaf(&self, seed: &[u8; SEED_BYTES], rep: usize, index: usize) -> Vec<u128> {
        let mut input = Vec::with_capacity(DOMAIN.len() + 11 + SEED_BYTES);
        input.extend_from_slice(DOMAIN);
        input.extend_from_slice(b"|vec|");
        input.extend_from_slice(&(rep as u16).to_be_bytes());
        input.extend_from_slice(&(index as u32).to_be_bytes());
        input.extend_from_slice(seed);
        let blob = shake(&input, self.blob_bytes());
        let stride = self.slot_bytes();
        (0..self.length)
            .map(|slot| field_from_191_bits(&blob[slot * stride..slot * stride + stride]))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct LinearProof {
    pub root: [u8; COMMIT_BYTES],
    pub witness_correction: Vec<u128>,
    pub vole_corrections: Vec<Vec<u128>>,
    pub opening: u128,
    pub tags: Vec<u128>,
    pub copaths: Vec<Vec<[u8; SEED_BYTES]>>,
    pub punctured: Vec<[u8; COMMIT_BYTES]>,
    pub depth: usize,
    pub repeats: usize,
}

impl LinearProof {
    pub fn soundness_bits(&self) -> usize {
        self.depth * self.repeats
    }

    pub fn size_breakdown(&self) -> [(&'static str, usize); 7] {
        let n = self.witness_correction.len();
        [
            ("root", COMMIT_BYTES),
            ("witness_correction", n * 16),
            ("vole_corrections", self.vole_corrections.len() * n * 16),
            ("opening", 16),
            ("tags", self.tags.len() * 16),
            (
                "copaths",
                self.copaths.iter().map(Vec::len).sum::<usize>() * SEED_BYTES,
            ),
            ("punctured", self.punctured.len() * COMMIT_BYTES),
        ]
    }

    pub fn size_bytes(&self) -> usize {
        self.size_breakdown().iter().map(|(_, value)| value).sum()
    }
}

struct Committed {
    values: Vec<u128>,
    vs: Vec<Vec<u128>>,
    root: [u8; COMMIT_BYTES],
    witness_correction: Vec<u128>,
    vole_corrections: Vec<Vec<u128>>,
}

/// A VOLE-in-the-Head commitment is deliberately one-use.
///
/// Keeping the two phases explicit mirrors the protocol: coefficients are
/// derived only after `commit`, and publishing one Fiat--Shamir challenge in
/// `prove` spends the commitment.  [`prove`] below remains the convenient
/// one-shot API used by the measurement harness.
pub struct Prover {
    depth: usize,
    repeats: usize,
    roots: Vec<[u8; SEED_BYTES]>,
    committed: Option<Committed>,
    proved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoleCommitment {
    pub root: [u8; COMMIT_BYTES],
    pub witness_correction: Vec<u128>,
    pub vole_corrections: Vec<Vec<u128>>,
}

impl Prover {
    pub fn new<R: RngCore + CryptoRng>(
        depth: usize,
        repeats: usize,
        rng: &mut R,
    ) -> Result<Self, String> {
        if depth == 0 || repeats == 0 || depth >= usize::BITS as usize {
            return Err("a tree needs a level and a proof needs a repetition".into());
        }
        let mut roots = vec![[0u8; SEED_BYTES]; repeats];
        for root in &mut roots {
            rng.fill_bytes(root);
        }
        Ok(Self {
            depth,
            repeats,
            roots,
            committed: None,
            proved: false,
        })
    }

    pub fn commit(&mut self, values: &[u128]) -> Result<VoleCommitment, String> {
        if self.committed.is_some() {
            return Err("this commitment is already made; build another Prover".into());
        }
        if values.is_empty() {
            return Err("a proof over no values proves nothing".into());
        }
        let packing = Packing {
            length: values.len(),
            depth: self.depth,
        };
        let mut us = Vec::with_capacity(self.repeats);
        let mut vs = Vec::with_capacity(self.repeats);
        let mut commitments =
            Vec::with_capacity(self.repeats * (1usize << self.depth) * COMMIT_BYTES);
        for (rep, root_seed) in self.roots.iter().enumerate() {
            let leaves = expand_tree(root_seed, self.depth, rep);
            let mut u = vec![0u128; values.len()];
            let mut weighted = vec![0u128; values.len()];
            for (index, leaf) in leaves.iter().enumerate() {
                let fields = packing.leaf(leaf, rep, index);
                for position in 0..values.len() {
                    u[position] = add_mod(u[position], fields[position]);
                    weighted[position] =
                        add_mod(weighted[position], mul_mod(fields[position], index as u128));
                }
                commitments.extend_from_slice(&leaf_commitment(leaf, rep, index));
            }
            us.push(u);
            vs.push(weighted.into_iter().map(neg_mod).collect::<Vec<_>>());
        }
        let mut root_input = Vec::with_capacity(DOMAIN.len() + 6 + commitments.len());
        root_input.extend_from_slice(DOMAIN);
        root_input.extend_from_slice(b"|root|");
        root_input.extend_from_slice(&commitments);
        let root: [u8; COMMIT_BYTES] = shake(&root_input, COMMIT_BYTES).try_into().unwrap();
        let reference = &us[0];
        let witness_correction = values
            .iter()
            .zip(reference)
            .map(|(&value, &mask)| sub_mod(value % P, mask))
            .collect::<Vec<_>>();
        let vole_corrections = us
            .iter()
            .skip(1)
            .map(|row| {
                reference
                    .iter()
                    .zip(row)
                    .map(|(&a, &b)| sub_mod(a, b))
                    .collect()
            })
            .collect::<Vec<Vec<u128>>>();
        self.committed = Some(Committed {
            values: values.iter().map(|value| value % P).collect(),
            vs,
            root,
            witness_correction: witness_correction.clone(),
            vole_corrections: vole_corrections.clone(),
        });
        Ok(VoleCommitment {
            root,
            witness_correction,
            vole_corrections,
        })
    }

    pub fn prove(&mut self, coeffs: &[u64], context: &[u8]) -> Result<LinearProof, String> {
        let Some(committed) = self.committed.as_ref() else {
            return Err("commit before proving; the coefficients need the root".into());
        };
        if self.proved {
            return Err("these commitments open once; build another Prover".into());
        }
        if coeffs.len() != committed.values.len() {
            return Err("one coefficient per value".into());
        }
        let opening = inner_product(coeffs, &committed.values);
        let tags = committed
            .vs
            .iter()
            .map(|row| inner_product(coeffs, row))
            .collect::<Vec<_>>();
        let deltas = challenge(
            &committed.root,
            &committed.witness_correction,
            &committed.vole_corrections,
            opening,
            &tags,
            context,
            self.depth,
            self.repeats,
        );
        let mut copaths = Vec::with_capacity(self.repeats);
        let mut punctured = Vec::with_capacity(self.repeats);
        for (rep, delta) in deltas.into_iter().enumerate() {
            copaths.push(copath(&self.roots[rep], self.depth, rep, delta)?);
            let leaves = expand_tree(&self.roots[rep], self.depth, rep);
            punctured.push(leaf_commitment(&leaves[delta], rep, delta));
        }
        let proof = LinearProof {
            root: committed.root,
            witness_correction: committed.witness_correction.clone(),
            vole_corrections: committed.vole_corrections.clone(),
            opening,
            tags,
            copaths,
            punctured,
            depth: self.depth,
            repeats: self.repeats,
        };
        self.proved = true;
        Ok(proof)
    }
}

pub fn prove<R: RngCore + CryptoRng>(
    values: &[u128],
    context: &[u8],
    depth: usize,
    repeats: usize,
    rng: &mut R,
) -> Result<LinearProof, String> {
    let mut prover = Prover::new(depth, repeats, rng)?;
    let commitment = prover.commit(values)?;
    let coeffs = coefficients(
        &commitment.root,
        &commitment.witness_correction,
        context,
        40,
        values.len(),
    );
    prover.prove(&coeffs, context)
}

pub fn verify(proof: &LinearProof, context: &[u8]) -> (bool, String) {
    let coeffs = coefficients(
        &proof.root,
        &proof.witness_correction,
        context,
        40,
        proof.witness_correction.len(),
    );
    verify_with_coefficients(proof, &coeffs, context)
}

/// Lower-level verifier for the explicit commit-then-prove seam.
///
/// The public one-shot seam derives these coefficients itself in [`verify`].
/// Keeping this entry point makes it possible to verify that changing a proof
/// field cannot silently change the statement that was fixed after commit.
pub fn verify_with_coefficients(
    proof: &LinearProof,
    coeffs: &[u64],
    context: &[u8],
) -> (bool, String) {
    let n = proof.witness_correction.len();
    if n == 0 {
        return (false, "the proof covers no values".into());
    }
    if proof.depth == 0
        || proof.repeats == 0
        || proof.depth >= usize::BITS as usize
        || proof.depth >= u64::BITS as usize
    {
        return (
            false,
            "a tree needs a level and a proof needs a repetition".into(),
        );
    }
    if coeffs.len() != n {
        return (false, "one coefficient per value".into());
    }
    if proof.vole_corrections.len() != proof.repeats - 1 {
        return (
            false,
            "one VOLE correction per repetition after the first".into(),
        );
    }
    if proof.copaths.len() != proof.repeats || proof.punctured.len() != proof.repeats {
        return (false, "one opening per repetition".into());
    }
    if proof.tags.len() != proof.repeats {
        return (false, "one tag per repetition".into());
    }
    if proof
        .vole_corrections
        .iter()
        .any(|correction| correction.len() != n)
    {
        return (false, "one VOLE correction per value".into());
    }
    let deltas = challenge(
        &proof.root,
        &proof.witness_correction,
        &proof.vole_corrections,
        proof.opening,
        &proof.tags,
        context,
        proof.depth,
        proof.repeats,
    );
    let packing = Packing {
        length: n,
        depth: proof.depth,
    };
    let mut commitments =
        Vec::with_capacity(proof.repeats * (1usize << proof.depth) * COMMIT_BYTES);
    for (rep, &delta) in deltas.iter().enumerate() {
        let Ok(leaves) = open_copath(&proof.copaths[rep], proof.depth, rep, delta) else {
            return (false, format!("repetition {rep} has an invalid co-path"));
        };
        let mut totals = vec![0u128; n];
        let mut weighted = vec![0u128; n];
        for (index, leaf) in leaves.iter().enumerate() {
            let Some(leaf) = leaf else {
                if index == delta {
                    commitments.extend_from_slice(&proof.punctured[rep]);
                    continue;
                }
                return (
                    false,
                    format!("repetition {rep} left leaf {index} unopened"),
                );
            };
            let fields = packing.leaf(leaf, rep, index);
            for position in 0..n {
                totals[position] = add_mod(totals[position], fields[position]);
                weighted[position] =
                    add_mod(weighted[position], mul_mod(fields[position], index as u128));
            }
            commitments.extend_from_slice(&leaf_commitment(leaf, rep, index));
        }
        let shift = if rep == 0 {
            proof.witness_correction.clone()
        } else {
            proof
                .witness_correction
                .iter()
                .zip(&proof.vole_corrections[rep - 1])
                .map(|(&a, &b)| add_mod(a, b))
                .collect()
        };
        let mut combined = 0;
        for position in 0..n {
            let q = add_mod(
                sub_mod(mul_mod(delta as u128, totals[position]), weighted[position]),
                mul_mod(delta as u128, shift[position]),
            );
            combined = add_mod(combined, mul_mod(coeffs[position] as u128, q));
        }
        let expected = add_mod(mul_mod(proof.opening, delta as u128), proof.tags[rep]);
        if combined != expected {
            return (
                false,
                format!(
                    "repetition {rep} does not hold: the values the opening combines are not the committed ones"
                ),
            );
        }
    }
    let mut root_input = Vec::with_capacity(DOMAIN.len() + 6 + commitments.len());
    root_input.extend_from_slice(DOMAIN);
    root_input.extend_from_slice(b"|root|");
    root_input.extend_from_slice(&commitments);
    if shake(&root_input, COMMIT_BYTES).as_slice() != proof.root {
        return (false, "the opened leaves are not the committed ones".into());
    }
    (true, "ok".into())
}

pub fn proof_size(n_values: usize, depth: usize, repeats: usize) -> [(&'static str, usize); 10] {
    let parts = [
        ("root", COMMIT_BYTES),
        ("witness_correction", n_values * 16),
        (
            "vole_corrections",
            repeats.saturating_sub(1) * n_values * 16,
        ),
        ("opening", 16),
        ("tags", repeats * 16),
        ("copaths", repeats * depth * SEED_BYTES),
        ("punctured", repeats * COMMIT_BYTES),
    ];
    let total = parts.iter().map(|(_, value)| value).sum();
    [
        parts[0],
        parts[1],
        parts[2],
        parts[3],
        parts[4],
        parts[5],
        parts[6],
        ("total", total),
        ("hashes", repeats * (1usize << depth) * 2),
        ("soundness_bits", depth * repeats),
    ]
}

pub fn expand_tree(root: &[u8; SEED_BYTES], depth: usize, rep: usize) -> Vec<[u8; SEED_BYTES]> {
    let mut level = vec![*root];
    for tree_depth in 0..depth {
        let mut next = Vec::with_capacity(level.len() * 2);
        for seed in &level {
            let (left, right) = prg(seed, rep, tree_depth);
            next.push(left);
            next.push(right);
        }
        level = next;
    }
    level
}

fn copath(
    root: &[u8; SEED_BYTES],
    depth: usize,
    rep: usize,
    index: usize,
) -> Result<Vec<[u8; SEED_BYTES]>, String> {
    if index >= (1usize << depth) {
        return Err(format!("leaf {index} is outside a depth-{depth} tree"));
    }
    let mut out = Vec::with_capacity(depth);
    let mut seed = *root;
    for tree_depth in 0..depth {
        let bit = (index >> (depth - 1 - tree_depth)) & 1;
        let (left, right) = prg(&seed, rep, tree_depth);
        out.push(if bit == 0 { right } else { left });
        seed = if bit == 0 { left } else { right };
    }
    Ok(out)
}

fn open_copath(
    path: &[[u8; SEED_BYTES]],
    depth: usize,
    rep: usize,
    index: usize,
) -> Result<Vec<Option<[u8; SEED_BYTES]>>, String> {
    if path.len() != depth {
        return Err(format!("a depth-{depth} tree has a {depth}-seed co-path"));
    }
    let mut leaves = vec![None; 1usize << depth];
    for (tree_depth, &sibling) in path.iter().enumerate() {
        let bit = (index >> (depth - 1 - tree_depth)) & 1;
        let prefix = index >> (depth - tree_depth);
        let sub_index = (prefix << 1) | (1 - bit);
        let span = 1usize << (depth - 1 - tree_depth);
        let base = sub_index * span;
        let mut level = vec![sibling];
        for deeper in tree_depth + 1..depth {
            let mut next = Vec::with_capacity(level.len() * 2);
            for seed in &level {
                let (left, right) = prg(seed, rep, deeper);
                next.push(left);
                next.push(right);
            }
            level = next;
        }
        for (offset, leaf) in level.into_iter().enumerate() {
            leaves[base + offset] = Some(leaf);
        }
    }
    Ok(leaves)
}

fn prg(seed: &[u8; SEED_BYTES], rep: usize, depth: usize) -> ([u8; 16], [u8; 16]) {
    let mut input = Vec::with_capacity(DOMAIN.len() + 5 + 4 + SEED_BYTES);
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(b"|prg|");
    input.extend_from_slice(&(rep as u16).to_be_bytes());
    input.extend_from_slice(&(depth as u16).to_be_bytes());
    input.extend_from_slice(seed);
    let output = shake(&input, 2 * SEED_BYTES);
    (
        output[..SEED_BYTES].try_into().unwrap(),
        output[SEED_BYTES..].try_into().unwrap(),
    )
}

fn leaf_commitment(seed: &[u8; SEED_BYTES], rep: usize, index: usize) -> [u8; COMMIT_BYTES] {
    let mut input = Vec::with_capacity(DOMAIN.len() + 6 + 6 + SEED_BYTES);
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(b"|leaf|");
    input.extend_from_slice(&(rep as u16).to_be_bytes());
    input.extend_from_slice(&(index as u32).to_be_bytes());
    input.extend_from_slice(seed);
    shake(&input, COMMIT_BYTES).try_into().unwrap()
}

pub fn coefficients(
    root: &[u8; COMMIT_BYTES],
    correction: &[u128],
    context: &[u8],
    challenge_bits: usize,
    count: usize,
) -> Vec<u64> {
    let mut hasher = Sha512::new();
    Digest::update(&mut hasher, DOMAIN);
    Digest::update(&mut hasher, b"|coeff|");
    absorb(&mut hasher, context);
    absorb(&mut hasher, root);
    absorb(&mut hasher, &ints(correction));
    Digest::update(&mut hasher, (count as u32).to_be_bytes());
    let base = hasher.finalize();
    let span = (1u64 << challenge_bits) - 1;
    (0..count)
        .map(|index| {
            let mut hasher = Sha512::new();
            Digest::update(&mut hasher, base);
            Digest::update(&mut hasher, (index as u32).to_be_bytes());
            1 + bytes_mod(&hasher.finalize(), span)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn challenge(
    root: &[u8; COMMIT_BYTES],
    correction: &[u128],
    vole_corrections: &[Vec<u128>],
    opening: u128,
    tags: &[u128],
    context: &[u8],
    depth: usize,
    repeats: usize,
) -> Vec<usize> {
    let mut hasher = Sha512::new();
    Digest::update(&mut hasher, DOMAIN);
    Digest::update(&mut hasher, b"|delta|");
    absorb(&mut hasher, context);
    absorb(&mut hasher, root);
    absorb(&mut hasher, &ints(correction));
    for row in vole_corrections {
        absorb(&mut hasher, &ints(row));
    }
    absorb(&mut hasher, &opening.to_be_bytes());
    absorb(&mut hasher, &ints(tags));
    let base = hasher.finalize();
    let span = 1u128 << depth;
    (0..repeats)
        .map(|rep| {
            let mut hasher = Sha512::new();
            Digest::update(&mut hasher, base);
            Digest::update(&mut hasher, (rep as u32).to_be_bytes());
            bytes_mod_u128(&hasher.finalize(), span) as usize
        })
        .collect()
}

fn absorb(hasher: &mut Sha512, part: &[u8]) {
    Digest::update(hasher, (part.len() as u32).to_be_bytes());
    Digest::update(hasher, part);
}

fn ints(values: &[u128]) -> Vec<u8> {
    let mut output = Vec::with_capacity(values.len() * 16);
    for value in values {
        output.extend_from_slice(&value.to_be_bytes());
    }
    output
}

fn shake(input: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; length];
    reader.read(&mut output);
    output
}

fn field_from_191_bits(slot: &[u8]) -> u128 {
    let mut low_bytes = [0u8; 16];
    low_bytes.copy_from_slice(&slot[..16]);
    let base = u128::from_le_bytes(low_bytes);
    let low = base & P;
    let mut high = base >> 127;
    for (offset, &byte) in slot[16..24].iter().enumerate() {
        let byte = if offset == 7 { byte & 0x7f } else { byte };
        high |= (byte as u128) << (1 + 8 * offset);
    }
    let sum = low + high;
    if sum >= P {
        sum - P
    } else {
        sum
    }
}

fn bytes_mod(bytes: &[u8], modulus: u64) -> u64 {
    bytes.iter().fold(0u64, |acc, byte| {
        ((acc as u128 * 256 + *byte as u128) % modulus as u128) as u64
    })
}

fn bytes_mod_u128(bytes: &[u8], modulus: u128) -> u128 {
    bytes.iter().fold(0u128, |acc, byte| {
        add_mod_u128_product(acc, 256, *byte as u128, modulus)
    })
}

fn add_mod_u128_product(left: u128, factor: u128, right: u128, modulus: u128) -> u128 {
    // The challenge modulus is at most 2^63 in proofs and exactly 2^64 in the
    // transcript-coverage test, so this product cannot overflow u128.
    (left * factor + right) % modulus
}

fn inner_product(coefficients: &[u64], values: &[u128]) -> u128 {
    coefficients
        .iter()
        .zip(values)
        .fold(0, |sum, (&coefficient, &value)| {
            add_mod(sum, mul_mod(coefficient as u128, value % P))
        })
}

pub fn add_mod(a: u128, b: u128) -> u128 {
    let sum = a + b;
    if sum >= P {
        sum - P
    } else {
        sum
    }
}

pub fn sub_mod(a: u128, b: u128) -> u128 {
    if a >= b {
        a - b
    } else {
        P - (b - a)
    }
}

pub fn neg_mod(value: u128) -> u128 {
    if value == 0 {
        0
    } else {
        P - value
    }
}

pub fn mul_mod(mut left: u128, mut right: u128) -> u128 {
    left %= P;
    let mut result = 0;
    while right != 0 {
        if right & 1 == 1 {
            result = add_mod(result, left);
        }
        left = add_mod(left, left);
        right >>= 1;
    }
    result
}

pub fn shake_raw(input: &[u8], length: usize) -> Vec<u8> {
    shake(input, length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const CONTEXT: &[u8] = b"ctx";

    fn values(count: usize) -> Vec<u128> {
        (0..count)
            .map(|index| (index as u128 + 1) * 37 + 5)
            .collect()
    }

    fn make(
        count: usize,
        depth: usize,
        repeats: usize,
        context: &[u8],
    ) -> (Vec<u128>, Vec<u64>, LinearProof) {
        let vals = values(count);
        let mut rng =
            StdRng::seed_from_u64(0x564f_4c45_6974_6800 ^ count as u64 ^ ((depth as u64) << 8));
        let mut prover = Prover::new(depth, repeats, &mut rng).unwrap();
        let commitment = prover.commit(&vals).unwrap();
        let coeffs = coefficients(
            &commitment.root,
            &commitment.witness_correction,
            context,
            40,
            vals.len(),
        );
        let proof = prover.prove(&coeffs, context).unwrap();
        (vals, coeffs, proof)
    }

    fn assert_honest_then_refused(
        honest: &LinearProof,
        forged: &LinearProof,
        coeffs: &[u64],
        context: &[u8],
        expected_check: &str,
    ) {
        assert_eq!(
            verify_with_coefficients(honest, coeffs, context),
            (true, "ok".into()),
            "the control proof must reach and pass the check under test"
        );
        let (ok, why) = verify_with_coefficients(forged, coeffs, context);
        assert!(!ok, "tampering was accepted");
        assert!(
            why.contains(expected_check),
            "tampering was refused by the wrong check: {why}"
        );
    }

    #[test]
    fn copath_opens_every_leaf_but_one() {
        for depth in [1usize, 2, 3, 5, 8] {
            let root = [depth as u8; SEED_BYTES];
            let leaves = expand_tree(&root, depth, 0);
            assert_eq!(leaves.len(), 1usize << depth);
            for index in 0..1usize << depth {
                let opened =
                    open_copath(&copath(&root, depth, 0, index).unwrap(), depth, 0, index).unwrap();
                assert!(opened[index].is_none(), "punctured leaf {index} was opened");
                for other in 0..1usize << depth {
                    if other != index {
                        assert_eq!(opened[other], Some(leaves[other]), "({index}, {other})");
                    }
                }
            }
        }
    }

    #[test]
    fn copath_is_log_sized() {
        assert_eq!(copath(&[7; SEED_BYTES], 10, 0, 512).unwrap().len(), 10);
    }

    #[test]
    fn copath_rejects_an_index_outside_the_tree() {
        let error = copath(&[7; SEED_BYTES], 4, 0, 16).unwrap_err();
        assert!(error.contains("outside a depth-4 tree"));
    }

    #[test]
    fn trees_at_different_repetitions_differ() {
        let root = [11; SEED_BYTES];
        assert_ne!(expand_tree(&root, 4, 0), expand_tree(&root, 4, 1));
    }

    #[test]
    fn a_leaf_commitment_binds_its_index_and_repetition() {
        let leaf = [13; SEED_BYTES];
        let mut seen = std::collections::HashSet::new();
        for repetition in 0..3 {
            for index in 0..3 {
                seen.insert(leaf_commitment(&leaf, repetition, index));
            }
        }
        assert_eq!(seen.len(), 9);
    }

    #[test]
    fn the_vole_correlation_holds() {
        for depth in [3usize, 6] {
            let count = 4;
            let repetition = 0;
            let root = [depth as u8 + 17; SEED_BYTES];
            let packing = Packing {
                length: count,
                depth,
            };
            let leaves = expand_tree(&root, depth, repetition);
            let mut u = vec![0u128; count];
            let mut weighted = vec![0u128; count];
            for (index, leaf) in leaves.iter().enumerate() {
                let fields = packing.leaf(leaf, repetition, index);
                for position in 0..count {
                    u[position] = add_mod(u[position], fields[position]);
                    weighted[position] =
                        add_mod(weighted[position], mul_mod(index as u128, fields[position]));
                }
            }
            let v = weighted.into_iter().map(neg_mod).collect::<Vec<_>>();
            let delta = (1usize << depth) - 2;
            let opened = open_copath(
                &copath(&root, depth, repetition, delta).unwrap(),
                depth,
                repetition,
                delta,
            )
            .unwrap();
            let mut totals = vec![0u128; count];
            let mut weights = vec![0u128; count];
            for (index, leaf) in opened.iter().enumerate() {
                let Some(leaf) = leaf else { continue };
                let fields = packing.leaf(leaf, repetition, index);
                for position in 0..count {
                    totals[position] = add_mod(totals[position], fields[position]);
                    weights[position] =
                        add_mod(weights[position], mul_mod(index as u128, fields[position]));
                }
            }
            for position in 0..count {
                let q = sub_mod(mul_mod(delta as u128, totals[position]), weights[position]);
                assert_eq!(
                    q,
                    add_mod(mul_mod(delta as u128, u[position]), v[position]),
                    "depth {depth}, field position {position}"
                );
            }
        }
    }

    #[test]
    fn packing_leaves_room_for_every_sum() {
        for depth in [4usize, 8, 12, 16] {
            let packing = Packing { length: 200, depth };
            let widest_bits = packing.value_bits() + 2 * depth;
            assert!(widest_bits < packing.slot_bytes() * 8, "depth {depth}");
        }
    }

    #[test]
    fn leaf_values_reach_past_the_modulus() {
        let packing = Packing {
            length: 4,
            depth: 8,
        };
        assert!(packing.value_bits() >= P.ilog2() as usize + 1 + 64);
    }

    #[test]
    fn an_honest_proof_verifies() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        assert_eq!(
            verify_with_coefficients(&proof, &coeffs, CONTEXT),
            (true, "ok".into())
        );
    }

    #[test]
    fn the_opening_is_the_combination() {
        let (vals, coeffs, proof) = make(12, 5, 4, CONTEXT);
        assert_eq!(proof.opening, inner_product(&coeffs, &vals));
    }

    #[test]
    fn it_verifies_at_every_shape() {
        for (depth, repeats) in [(2usize, 3usize), (4, 4), (6, 2), (8, 2)] {
            let (_, coeffs, proof) = make(7, depth, repeats, CONTEXT);
            assert!(verify_with_coefficients(&proof, &coeffs, CONTEXT).0);
            assert_eq!(proof.soundness_bits(), depth * repeats);
        }
    }

    #[test]
    fn one_value_is_allowed_and_none_is_not() {
        assert_eq!(make(1, 4, 2, CONTEXT).2.witness_correction.len(), 1);
        let mut rng = StdRng::seed_from_u64(12);
        let mut prover = Prover::new(4, 2, &mut rng).unwrap();
        assert_eq!(
            prover.commit(&[]).unwrap_err(),
            "a proof over no values proves nothing"
        );
    }

    #[test]
    fn a_degenerate_shape_is_refused() {
        let mut rng = StdRng::seed_from_u64(13);
        assert!(Prover::new(0, 4, &mut rng).is_err());
        assert!(Prover::new(4, 0, &mut rng).is_err());
    }

    #[test]
    fn a_changed_opening_is_caught() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        let mut forged = proof.clone();
        forged.opening = add_mod(forged.opening, 1);
        assert_honest_then_refused(&proof, &forged, &coeffs, CONTEXT, "does not hold");
    }

    #[test]
    fn a_changed_witness_correction_is_caught() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        let mut forged = proof.clone();
        forged.witness_correction[0] = add_mod(forged.witness_correction[0], 1);
        assert_honest_then_refused(&proof, &forged, &coeffs, CONTEXT, "does not hold");
    }

    #[test]
    fn a_changed_vole_correction_is_caught() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        let mut forged = proof.clone();
        forged.vole_corrections[0][0] = add_mod(forged.vole_corrections[0][0], 1);
        assert_honest_then_refused(&proof, &forged, &coeffs, CONTEXT, "does not hold");
    }

    #[test]
    fn a_changed_tag_is_caught() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        let mut forged = proof.clone();
        forged.tags[0] = add_mod(forged.tags[0], 1);
        assert_honest_then_refused(&proof, &forged, &coeffs, CONTEXT, "does not hold");
    }

    #[test]
    fn a_swapped_copath_seed_is_caught() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        let mut forged = proof.clone();
        let replacement = [0xa5; SEED_BYTES];
        assert_ne!(forged.copaths[0][0], replacement);
        forged.copaths[0][0] = replacement;
        assert_honest_then_refused(&proof, &forged, &coeffs, CONTEXT, "does not hold");
    }

    #[test]
    fn a_swapped_punctured_commitment_is_caught() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        let mut forged = proof.clone();
        let replacement = [0xa5; COMMIT_BYTES];
        assert_ne!(forged.punctured[0], replacement);
        forged.punctured[0] = replacement;
        assert_honest_then_refused(
            &proof,
            &forged,
            &coeffs,
            CONTEXT,
            "opened leaves are not the committed ones",
        );
    }

    #[test]
    fn a_changed_root_is_caught() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        let mut forged = proof.clone();
        let replacement = [0xa5; COMMIT_BYTES];
        assert_ne!(forged.root, replacement);
        forged.root = replacement;
        assert_honest_then_refused(&proof, &forged, &coeffs, CONTEXT, "does not hold");
    }

    #[test]
    fn another_context_does_not_verify() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        assert_eq!(
            verify_with_coefficients(&proof, &coeffs, CONTEXT),
            (true, "ok".into())
        );
        let (ok, why) = verify_with_coefficients(&proof, &coeffs, b"a different auction");
        assert!(!ok);
        assert!(why.contains("does not hold"), "wrong refusal check: {why}");
    }

    #[test]
    fn changed_coefficients_do_not_verify() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        let mut forged_coeffs = coeffs.clone();
        forged_coeffs[0] += 1;
        assert_eq!(
            verify_with_coefficients(&proof, &coeffs, CONTEXT),
            (true, "ok".into())
        );
        let (ok, why) = verify_with_coefficients(&proof, &forged_coeffs, CONTEXT);
        assert!(!ok);
        assert!(why.contains("does not hold"), "wrong refusal check: {why}");
    }

    #[test]
    fn a_substituted_value_cannot_be_proved() {
        let (vals, coeffs, proof) = make(9, 5, 4, CONTEXT);
        let mut substituted = vals;
        substituted[0] += 1;
        let mut forged = proof.clone();
        forged.opening = inner_product(&coeffs, &substituted);
        assert_honest_then_refused(&proof, &forged, &coeffs, CONTEXT, "does not hold");
    }

    #[test]
    fn a_malformed_shape_is_rejected_rather_than_crashing() {
        let (_, coeffs, proof) = make(12, 5, 4, CONTEXT);
        assert_eq!(
            verify_with_coefficients(&proof, &coeffs, CONTEXT),
            (true, "ok".into())
        );

        let mut no_corrections = proof.clone();
        no_corrections.vole_corrections.clear();
        let refused = verify_with_coefficients(&no_corrections, &coeffs, CONTEXT);
        assert!(!refused.0 && refused.1.contains("one VOLE correction per repetition"));

        let mut one_copath = proof.clone();
        one_copath.copaths.truncate(1);
        let refused = verify_with_coefficients(&one_copath, &coeffs, CONTEXT);
        assert!(!refused.0 && refused.1.contains("one opening per repetition"));

        let refused = verify_with_coefficients(&proof, &coeffs[..coeffs.len() - 1], CONTEXT);
        assert!(!refused.0 && refused.1.contains("one coefficient per value"));
    }

    #[test]
    fn a_second_proof_is_refused() {
        let mut rng = StdRng::seed_from_u64(17);
        let mut prover = Prover::new(4, 3, &mut rng).unwrap();
        let commitment = prover.commit(&values(5)).unwrap();
        let coeffs = coefficients(
            &commitment.root,
            &commitment.witness_correction,
            CONTEXT,
            40,
            5,
        );
        prover.prove(&coeffs, CONTEXT).unwrap();
        let error = prover.prove(&coeffs, b"another statement").unwrap_err();
        assert!(error.contains("open once"));
    }

    #[test]
    fn a_second_commitment_is_refused() {
        let mut rng = StdRng::seed_from_u64(19);
        let mut prover = Prover::new(4, 3, &mut rng).unwrap();
        prover.commit(&values(5)).unwrap();
        let error = prover.commit(&values(5)).unwrap_err();
        assert!(error.contains("already made"));
    }

    #[test]
    fn proving_before_committing_is_refused() {
        let mut rng = StdRng::seed_from_u64(23);
        let mut prover = Prover::new(4, 3, &mut rng).unwrap();
        let error = prover.prove(&[1, 2, 3], CONTEXT).unwrap_err();
        assert!(error.contains("commit before proving"));
    }

    #[test]
    fn coefficients_depend_on_the_commitment() {
        let root = [29; COMMIT_BYTES];
        assert_ne!(
            coefficients(&root, &[1, 2, 3], CONTEXT, 40, 3),
            coefficients(&root, &[1, 2, 4], CONTEXT, 40, 3)
        );
    }

    #[test]
    fn coefficients_depend_on_the_context() {
        let root = [31; COMMIT_BYTES];
        assert_ne!(
            coefficients(&root, &[1, 2, 3], b"a", 40, 3),
            coefficients(&root, &[1, 2, 3], b"b", 40, 3)
        );
    }

    #[test]
    fn no_coefficient_is_zero() {
        let correction = (0..64).map(|value| value as u128).collect::<Vec<_>>();
        assert!(
            coefficients(&[37; COMMIT_BYTES], &correction, CONTEXT, 8, 64)
                .into_iter()
                .all(|coefficient| coefficient > 0)
        );
    }

    #[test]
    fn the_challenge_covers_everything_the_prover_sends() {
        let root = [41; COMMIT_BYTES];
        let correction = vec![1, 2];
        let vole_corrections = vec![vec![3, 4]];
        let tags = vec![6, 7];
        let base = challenge(
            &root,
            &correction,
            &vole_corrections,
            5,
            &tags,
            CONTEXT,
            64,
            4,
        );
        assert_ne!(
            challenge(&root, &[1, 3], &vole_corrections, 5, &tags, CONTEXT, 64, 4,),
            base
        );
        assert_ne!(
            challenge(&root, &correction, &[vec![3, 5]], 5, &tags, CONTEXT, 64, 4,),
            base
        );
        assert_ne!(
            challenge(
                &root,
                &correction,
                &vole_corrections,
                6,
                &tags,
                CONTEXT,
                64,
                4,
            ),
            base
        );
        assert_ne!(
            challenge(
                &root,
                &correction,
                &vole_corrections,
                5,
                &[6, 8],
                CONTEXT,
                64,
                4,
            ),
            base
        );
        assert_ne!(
            challenge(
                &root,
                &correction,
                &vole_corrections,
                5,
                &tags,
                b"other",
                64,
                4,
            ),
            base
        );
        assert_ne!(
            challenge(
                &[43; COMMIT_BYTES],
                &correction,
                &vole_corrections,
                5,
                &tags,
                CONTEXT,
                64,
                4,
            ),
            base
        );
    }

    #[test]
    fn the_size_arithmetic_matches_a_real_proof() {
        let (_, _, proof) = make(12, 5, 4, CONTEXT);
        let predicted = proof_size(12, 5, 4);
        for (name, actual) in proof.size_breakdown() {
            assert_eq!(
                predicted.iter().find(|(part, _)| *part == name).unwrap().1,
                actual,
                "{name}"
            );
        }
    }

    #[test]
    fn the_corrections_are_what_dominates_over_a_prime_field() {
        let parts = proof_size(167, 8, 16);
        let part = |name| parts.iter().find(|(key, _)| *key == name).unwrap().1;
        assert!(part("vole_corrections") * 5 > part("total") * 4);
        assert!(part("copaths") * 10 < part("total"));
    }

    #[test]
    fn a_deeper_tree_trades_size_for_hashing() {
        let shallow = proof_size(167, 6, 22);
        let deep = proof_size(167, 12, 11);
        let part =
            |parts: &[(&str, usize)], name| parts.iter().find(|(key, _)| *key == name).unwrap().1;
        assert!(part(&deep, "total") < part(&shallow, "total"));
        assert!(part(&deep, "hashes") > part(&shallow, "hashes"));
        assert!(part(&deep, "soundness_bits").min(part(&shallow, "soundness_bits")) >= 128);
    }

    #[test]
    fn only_one_of_the_two_is_post_quantum() {
        assert!(!linear_proof_metadata("pedersen").unwrap().post_quantum);
        assert!(linear_proof_metadata("voleith").unwrap().post_quantum);
    }

    #[test]
    fn an_unknown_scheme_names_the_ones_that_exist() {
        let error = linear_proof_metadata("groth16").unwrap_err();
        assert!(error.contains("pedersen"));
        assert!(error.contains("voleith"));
    }
}
