//! Pluggable groups and proof operations used by the native benchmark.
//!
//! Production Rust uses the audited Ristretto-backed crates.  The benchmark is
//! also the historical optimisation ladder, however, so its four RFC 3526
//! MODP implementations remain here as measurement-only compatibility code.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Signed, Zero};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Instant;

use crate::{timing_summary, HarnessResult};

const DOMAIN: &[u8] = b"QOMM:ZK:v1";
pub const BACKENDS: [&str; 5] = [
    "modp_naive",
    "modp_inv",
    "modp_negexp",
    "modp_multiexp",
    "ed25519",
];

fn modp_p() -> &'static BigUint {
    static VALUE: OnceLock<BigUint> = OnceLock::new();
    VALUE.get_or_init(|| {
        BigUint::parse_bytes(
            concat!(
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08",
                "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B",
                "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9",
                "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6",
                "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8",
                "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D",
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C",
                "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
                "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF",
                "FFFFFFFF"
            )
            .as_bytes(),
            16,
        )
        .expect("the RFC 3526 group-14 prime is valid")
    })
}

fn modp_q() -> &'static BigUint {
    static VALUE: OnceLock<BigUint> = OnceLock::new();
    VALUE.get_or_init(|| (modp_p() - BigUint::one()) >> 1usize)
}

fn ed_order() -> &'static BigUint {
    static VALUE: OnceLock<BigUint> = OnceLock::new();
    VALUE.get_or_init(|| {
        (BigUint::one() << 252usize)
            + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
                .expect("the Ed25519 subgroup order is valid")
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    ModpNaive,
    ModpInverse,
    ModpNegExp,
    ModpMultiexp,
    Ed25519,
}

impl Backend {
    fn parse(name: &str) -> HarnessResult<Self> {
        match name {
            "modp_naive" => Ok(Self::ModpNaive),
            "modp_inv" => Ok(Self::ModpInverse),
            "modp_negexp" => Ok(Self::ModpNegExp),
            "modp_multiexp" => Ok(Self::ModpMultiexp),
            "ed25519" => Ok(Self::Ed25519),
            _ => Err(format!("unknown group {name}; choose from {BACKENDS:?}").into()),
        }
    }

    fn is_modp(self) -> bool {
        !matches!(self, Self::Ed25519)
    }
}

#[derive(Clone, Debug)]
enum Point {
    Modp(BigUint),
    Ed25519(EdwardsPoint),
}

#[derive(Clone, Copy, Debug)]
struct Group {
    backend: Backend,
}

impl Group {
    fn new(name: &str) -> HarnessResult<Self> {
        Ok(Self {
            backend: Backend::parse(name)?,
        })
    }

    fn order(self) -> &'static BigUint {
        if self.backend.is_modp() {
            modp_q()
        } else {
            ed_order()
        }
    }

    fn security_bits(self) -> u64 {
        if self.backend.is_modp() {
            112
        } else {
            126
        }
    }

    fn scalar_bytes(self) -> usize {
        self.order().bits().div_ceil(8) as usize
    }

    fn random_scalar(self) -> BigUint {
        self.random_scalar_with(&mut OsRng, false)
    }

    fn random_scalar_with(self, rng: &mut impl RngCore, allow_zero: bool) -> BigUint {
        if self.backend == Backend::Ed25519 {
            loop {
                let mut wide = [0u8; 64];
                rng.fill_bytes(&mut wide);
                let value =
                    BigUint::from_bytes_le(&Scalar::from_bytes_mod_order_wide(&wide).to_bytes());
                if allow_zero || !value.is_zero() {
                    return value;
                }
            }
        }
        random_below(rng, self.order(), allow_zero)
    }

    fn identity(self) -> Point {
        if self.backend.is_modp() {
            Point::Modp(BigUint::one())
        } else {
            Point::Ed25519(EdwardsPoint::identity())
        }
    }

    fn base_pow(self, scalar: &BigUint) -> Point {
        if self.backend.is_modp() {
            Point::Modp(BigUint::from(2u8).modpow(&(scalar % self.order()), modp_p()))
        } else {
            Point::Ed25519(ED25519_BASEPOINT_POINT * to_ed_scalar(scalar))
        }
    }

    fn point_pow(self, point: &Point, scalar: &BigUint) -> Point {
        match (self.backend.is_modp(), point) {
            (true, Point::Modp(point)) => {
                Point::Modp(point.modpow(&(scalar % self.order()), modp_p()))
            }
            (false, Point::Ed25519(point)) => Point::Ed25519(point * to_ed_scalar(scalar)),
            _ => panic!("point belongs to a different group"),
        }
    }

    fn mul(self, left: &Point, right: &Point) -> Point {
        match (self.backend.is_modp(), left, right) {
            (true, Point::Modp(left), Point::Modp(right)) => Point::Modp((left * right) % modp_p()),
            (false, Point::Ed25519(left), Point::Ed25519(right)) => Point::Ed25519(left + right),
            _ => panic!("points belong to different groups"),
        }
    }

    fn neg(self, point: &Point) -> Point {
        match (self.backend.is_modp(), point) {
            (true, Point::Modp(point)) => {
                Point::Modp(mod_inverse(point, modp_p()).expect("a group element has an inverse"))
            }
            (false, Point::Ed25519(point)) => Point::Ed25519(-point),
            _ => panic!("point belongs to a different group"),
        }
    }

    fn commit(self, base: &Point, s: &BigUint, point: &Point, c: &BigUint) -> Point {
        if !self.backend.is_modp() {
            return self.mul(
                &self.point_pow(base, s),
                &self.neg(&self.point_pow(point, c)),
            );
        }
        let (Point::Modp(base), Point::Modp(point)) = (base, point) else {
            panic!("point belongs to a different group")
        };
        let s = s % modp_q();
        let c = c % modp_q();
        let value = match self.backend {
            Backend::ModpNaive => {
                let point_c = point.modpow(&c, modp_p());
                let inverse = point_c.modpow(&(modp_p() - BigUint::from(2u8)), modp_p());
                (base.modpow(&s, modp_p()) * inverse) % modp_p()
            }
            Backend::ModpInverse => {
                let point_c = point.modpow(&c, modp_p());
                let inverse = mod_inverse(&point_c, modp_p()).expect("group element inverse");
                (base.modpow(&s, modp_p()) * inverse) % modp_p()
            }
            Backend::ModpNegExp => {
                let other = mod_sub(modp_q(), &c, modp_q());
                (base.modpow(&s, modp_p()) * point.modpow(&other, modp_p())) % modp_p()
            }
            Backend::ModpMultiexp => multiexp(base, &s, point, &c),
            Backend::Ed25519 => unreachable!(),
        };
        Point::Modp(value)
    }

    fn base_commit(self, s: &BigUint, point: &Point, c: &BigUint) -> Point {
        self.commit(&self.base_pow(&BigUint::one()), s, point, c)
    }

    fn hash_to_point(self, label: &[u8]) -> Point {
        for counter in 0u32..1_000_000 {
            if self.backend.is_modp() {
                let mut digest = Sha256::new();
                digest.update(DOMAIN);
                digest.update(b":h2p:");
                digest.update(label);
                digest.update(counter.to_be_bytes());
                let candidate = BigUint::from_bytes_be(&digest.finalize()) % modp_p();
                let candidate = candidate.modpow(&BigUint::from(2u8), modp_p());
                if !candidate.is_zero()
                    && candidate != BigUint::one()
                    && candidate != BigUint::from(2u8)
                {
                    return Point::Modp(candidate);
                }
            } else {
                let mut digest = Sha512::new();
                digest.update(DOMAIN);
                digest.update(b":h2p:");
                digest.update(label);
                digest.update(counter.to_be_bytes());
                let bytes: [u8; 64] = digest.finalize().into();
                let mut compressed = [0u8; 32];
                compressed.copy_from_slice(&bytes[..32]);
                if let Some(point) = CompressedEdwardsY(compressed).decompress() {
                    let cleared = point.mul_by_cofactor();
                    if !cleared.is_identity() {
                        return Point::Ed25519(cleared);
                    }
                }
            }
        }
        panic!("hash to point failed")
    }

    fn encode(self, point: &Point) -> Vec<u8> {
        match (self.backend.is_modp(), point) {
            (true, Point::Modp(point)) => {
                let mut encoded = vec![0u8; 256];
                let bytes = point.to_bytes_be();
                encoded[256 - bytes.len()..].copy_from_slice(&bytes);
                encoded
            }
            (false, Point::Ed25519(point)) => point.compress().to_bytes().to_vec(),
            _ => panic!("point belongs to a different group"),
        }
    }

    fn equal(self, left: &Point, right: &Point) -> bool {
        self.encode(left) == self.encode(right)
    }

    fn is_valid(self, point: &Point) -> bool {
        match (self.backend.is_modp(), point) {
            (true, Point::Modp(point)) => {
                point > &BigUint::one()
                    && point < &(modp_p() - BigUint::one())
                    && point.modpow(modp_q(), modp_p()) == BigUint::one()
            }
            (false, Point::Ed25519(point)) => !point.is_identity() && point.is_torsion_free(),
            _ => false,
        }
    }
}

fn random_below(rng: &mut impl RngCore, upper: &BigUint, allow_zero: bool) -> BigUint {
    let bytes_len = upper.bits().div_ceil(8) as usize;
    let excess = bytes_len * 8 - upper.bits() as usize;
    loop {
        let mut bytes = vec![0u8; bytes_len];
        rng.fill_bytes(&mut bytes);
        if excess > 0 {
            bytes[0] &= 0xff >> excess;
        }
        let value = BigUint::from_bytes_be(&bytes);
        if value < *upper && (allow_zero || !value.is_zero()) {
            return value;
        }
    }
}

fn to_ed_scalar(value: &BigUint) -> Scalar {
    let bytes = (value % ed_order()).to_bytes_le();
    let mut scalar = [0u8; 32];
    scalar[..bytes.len()].copy_from_slice(&bytes);
    Scalar::from_bytes_mod_order(scalar)
}

fn mod_sub(left: &BigUint, right: &BigUint, modulus: &BigUint) -> BigUint {
    if left >= right {
        (left - right) % modulus
    } else {
        (modulus - ((right - left) % modulus)) % modulus
    }
}

fn mod_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let mut old_r = modulus.to_bigint()?;
    let mut r = value.to_bigint()?;
    let mut old_t = BigInt::zero();
    let mut t = BigInt::one();
    while !r.is_zero() {
        let quotient = &old_r / &r;
        (old_r, r) = (r.clone(), old_r - &quotient * &r);
        (old_t, t) = (t.clone(), old_t - quotient * &t);
    }
    if old_r != BigInt::one() {
        return None;
    }
    let modulus = modulus.to_bigint()?;
    let mut result = old_t % &modulus;
    if result.is_negative() {
        result += modulus;
    }
    result.to_biguint()
}

fn multiexp(base: &BigUint, s: &BigUint, point: &BigUint, c: &BigUint) -> BigUint {
    let other = mod_sub(modp_q(), c, modp_q());
    let table = [
        BigUint::one(),
        base % modp_p(),
        point % modp_p(),
        (base * point) % modp_p(),
    ];
    let bits = s.bits().max(other.bits());
    let mut result = BigUint::one();
    for index in (0..bits).rev() {
        result = (&result * &result) % modp_p();
        let selector = usize::from(s.bit(index)) | (usize::from(other.bit(index)) << 1);
        if selector != 0 {
            result = (result * &table[selector]) % modp_p();
        }
    }
    result
}

#[derive(Clone)]
struct Statement {
    registry_id: String,
    points: Vec<Point>,
    scope: String,
    context_hash: String,
}

#[derive(Clone)]
struct OrProof {
    nullifier: Point,
    challenges: Vec<BigUint>,
    responses: Vec<BigUint>,
}

impl OrProof {
    fn size_bytes(&self, group: Group) -> usize {
        group.encode(&self.nullifier).len() + 2 * self.challenges.len() * group.scalar_bytes()
    }
}

fn or_challenge(
    group: Group,
    statement: &Statement,
    nullifier: &Point,
    commit_g: &[Point],
    commit_h: &[Point],
) -> BigUint {
    let canonical = format!(
        "{{\"context_hash\":\"{}\",\"registry_id\":\"{}\",\"scope\":\"{}\"}}",
        statement.context_hash, statement.registry_id, statement.scope
    );
    let mut digest = Sha512::new();
    digest.update(DOMAIN);
    digest.update(b":fs:");
    digest.update(canonical.as_bytes());
    for point in std::iter::once(nullifier)
        .chain(statement.points.iter())
        .chain(commit_g.iter())
        .chain(commit_h.iter())
    {
        let encoded = group.encode(point);
        digest.update((encoded.len() as u32).to_be_bytes());
        digest.update(encoded);
    }
    BigUint::from_bytes_be(&digest.finalize()) % group.order()
}

fn or_prove(
    group: Group,
    statement: &Statement,
    secret: &BigUint,
    index: usize,
) -> HarnessResult<OrProof> {
    if index >= statement.points.len() {
        return Err("the witness is not in this registry".into());
    }
    if !group.equal(&statement.points[index], &group.base_pow(secret)) {
        return Err("the secret does not open the point at that index".into());
    }
    let h_scope = group.hash_to_point(statement.scope.as_bytes());
    let nullifier = group.point_pow(&h_scope, secret);
    let n = statement.points.len();
    let mut challenges = vec![BigUint::zero(); n];
    let mut responses = vec![BigUint::zero(); n];
    let mut commit_g = vec![group.identity(); n];
    let mut commit_h = vec![group.identity(); n];
    let witness_nonce = group.random_scalar();
    for (position, point) in statement.points.iter().enumerate() {
        if position == index {
            commit_g[position] = group.base_pow(&witness_nonce);
            commit_h[position] = group.point_pow(&h_scope, &witness_nonce);
        } else {
            challenges[position] = group.random_scalar();
            responses[position] = group.random_scalar();
            commit_g[position] =
                group.base_commit(&responses[position], point, &challenges[position]);
            commit_h[position] = group.commit(
                &h_scope,
                &responses[position],
                &nullifier,
                &challenges[position],
            );
        }
    }
    let total = or_challenge(group, statement, &nullifier, &commit_g, &commit_h);
    let others = challenges
        .iter()
        .fold(BigUint::zero(), |sum, value| sum + value)
        % group.order();
    challenges[index] = mod_sub(&total, &others, group.order());
    responses[index] = (&witness_nonce + &challenges[index] * secret) % group.order();
    Ok(OrProof {
        nullifier,
        challenges,
        responses,
    })
}

fn or_verify(group: Group, statement: &Statement, proof: &OrProof) -> bool {
    let n = statement.points.len();
    if proof.challenges.len() != n
        || proof.responses.len() != n
        || !group.is_valid(&proof.nullifier)
        || proof
            .challenges
            .iter()
            .chain(&proof.responses)
            .any(|value| value >= group.order())
    {
        return false;
    }
    let h_scope = group.hash_to_point(statement.scope.as_bytes());
    let commit_g: Vec<_> = (0..n)
        .map(|i| {
            group.base_commit(
                &proof.responses[i],
                &statement.points[i],
                &proof.challenges[i],
            )
        })
        .collect();
    let commit_h: Vec<_> = (0..n)
        .map(|i| {
            group.commit(
                &h_scope,
                &proof.responses[i],
                &proof.nullifier,
                &proof.challenges[i],
            )
        })
        .collect();
    let expected = or_challenge(group, statement, &proof.nullifier, &commit_g, &commit_h);
    proof
        .challenges
        .iter()
        .fold(BigUint::zero(), |sum, value| sum + value)
        % group.order()
        == expected
}

fn build_registry(group: Group, size: usize, seed: u64) -> (Statement, Vec<BigUint>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut secrets = Vec::with_capacity(size);
    let mut points = Vec::with_capacity(size);
    for _ in 0..size {
        let secret = group.random_scalar_with(&mut rng, false);
        points.push(group.base_pow(&secret));
        secrets.push(secret);
    }
    (
        Statement {
            registry_id: "fixture".into(),
            points,
            scope: "qomm:quote:v1".into(),
            context_hash: hex::encode(Sha256::digest(b"context")),
        },
        secrets,
    )
}

#[derive(Clone)]
struct Pedersen {
    group: Group,
    g: Point,
    h: Point,
}

impl Pedersen {
    fn new(group: Group, label: &[u8]) -> Self {
        Self {
            group,
            g: group.base_pow(&BigUint::one()),
            h: group.hash_to_point(label),
        }
    }

    fn commit(&self, value: &BigUint, blinding: &BigUint) -> Point {
        self.group.mul(
            &self.group.point_pow(&self.g, value),
            &self.group.point_pow(&self.h, blinding),
        )
    }

    fn challenge(&self, parts: &[ChallengePart<'_>]) -> BigUint {
        let mut digest = Sha512::new();
        digest.update(DOMAIN);
        digest.update(b":ped:");
        for part in parts {
            let encoded = match part {
                ChallengePart::Bytes(bytes) => bytes.to_vec(),
                ChallengePart::Point(point) => self.group.encode(point),
            };
            digest.update((encoded.len() as u32).to_be_bytes());
            digest.update(encoded);
        }
        BigUint::from_bytes_be(&digest.finalize()) % self.group.order()
    }
}

enum ChallengePart<'a> {
    Bytes(&'a [u8]),
    Point(&'a Point),
}

#[derive(Clone)]
struct OpeningProof {
    commitment_t: Point,
    z_value: BigUint,
    z_blinding: BigUint,
}

fn prove_opening(
    key: &Pedersen,
    commitment: &Point,
    value: &BigUint,
    blinding: &BigUint,
    context: &[u8],
) -> OpeningProof {
    let k_value = key.group.random_scalar();
    let k_blinding = key.group.random_scalar();
    let commitment_t = key.commit(&k_value, &k_blinding);
    let challenge = key.challenge(&[
        ChallengePart::Bytes(b"open"),
        ChallengePart::Bytes(context),
        ChallengePart::Point(commitment),
        ChallengePart::Point(&commitment_t),
    ]);
    OpeningProof {
        commitment_t,
        z_value: (k_value + &challenge * value) % key.group.order(),
        z_blinding: (k_blinding + challenge * blinding) % key.group.order(),
    }
}

fn verify_opening(
    key: &Pedersen,
    commitment: &Point,
    proof: &OpeningProof,
    context: &[u8],
) -> bool {
    if !key.group.is_valid(&proof.commitment_t)
        || &proof.z_value >= key.group.order()
        || &proof.z_blinding >= key.group.order()
    {
        return false;
    }
    let challenge = key.challenge(&[
        ChallengePart::Bytes(b"open"),
        ChallengePart::Bytes(context),
        ChallengePart::Point(commitment),
        ChallengePart::Point(&proof.commitment_t),
    ]);
    let left = key.commit(&proof.z_value, &proof.z_blinding);
    let right = key.group.mul(
        &proof.commitment_t,
        &key.group.point_pow(commitment, &challenge),
    );
    key.group.equal(&left, &right)
}

#[derive(Clone)]
struct BitProof {
    t0: Point,
    t1: Point,
    c0: BigUint,
    c1: BigUint,
    z0: BigUint,
    z1: BigUint,
}

fn prove_bit(
    key: &Pedersen,
    commitment: &Point,
    bit: usize,
    blinding: &BigUint,
    context: &[u8],
) -> BitProof {
    let shifted = [
        commitment.clone(),
        key.group.mul(commitment, &key.group.neg(&key.g)),
    ];
    let real = bit;
    let fake = 1 - bit;
    let nonce = key.group.random_scalar();
    let t_real = key.group.point_pow(&key.h, &nonce);
    let c_fake = key.group.random_scalar();
    let z_fake = key.group.random_scalar();
    let t_fake = key.group.mul(
        &key.group.point_pow(&key.h, &z_fake),
        &key.group.neg(&key.group.point_pow(&shifted[fake], &c_fake)),
    );
    let (t0, t1) = if bit == 0 {
        (t_real, t_fake)
    } else {
        (t_fake, t_real)
    };
    let total = key.challenge(&[
        ChallengePart::Bytes(b"bit"),
        ChallengePart::Bytes(context),
        ChallengePart::Point(commitment),
        ChallengePart::Point(&t0),
        ChallengePart::Point(&t1),
    ]);
    let c_real = mod_sub(&total, &c_fake, key.group.order());
    let z_real = (nonce + &c_real * blinding) % key.group.order();
    if real == 0 {
        BitProof {
            t0,
            t1,
            c0: c_real,
            c1: c_fake,
            z0: z_real,
            z1: z_fake,
        }
    } else {
        BitProof {
            t0,
            t1,
            c0: c_fake,
            c1: c_real,
            z0: z_fake,
            z1: z_real,
        }
    }
}

fn verify_bit(key: &Pedersen, commitment: &Point, proof: &BitProof, context: &[u8]) -> bool {
    if !key.group.is_valid(&proof.t0)
        || !key.group.is_valid(&proof.t1)
        || [&proof.c0, &proof.c1, &proof.z0, &proof.z1]
            .into_iter()
            .any(|value| value >= key.group.order())
    {
        return false;
    }
    let total = key.challenge(&[
        ChallengePart::Bytes(b"bit"),
        ChallengePart::Bytes(context),
        ChallengePart::Point(commitment),
        ChallengePart::Point(&proof.t0),
        ChallengePart::Point(&proof.t1),
    ]);
    if (&proof.c0 + &proof.c1) % key.group.order() != total {
        return false;
    }
    let shifted = [
        commitment.clone(),
        key.group.mul(commitment, &key.group.neg(&key.g)),
    ];
    for (branch, challenge, response, t) in [
        (0usize, &proof.c0, &proof.z0, &proof.t0),
        (1usize, &proof.c1, &proof.z1, &proof.t1),
    ] {
        let left = key.group.point_pow(&key.h, response);
        let right = key
            .group
            .mul(t, &key.group.point_pow(&shifted[branch], challenge));
        if !key.group.equal(&left, &right) {
            return false;
        }
    }
    true
}

#[derive(Clone)]
struct RangeProof {
    bit_commitments: Vec<Point>,
    bit_proofs: Vec<BitProof>,
    linkage: OpeningProof,
    bits: usize,
}

#[derive(Clone)]
struct BoundedProof {
    above: RangeProof,
    below: RangeProof,
    bits: usize,
}

fn context_suffix(context: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(context.len() + suffix.len());
    value.extend_from_slice(context);
    value.extend_from_slice(suffix);
    value
}

fn prove_range(
    key: &Pedersen,
    commitment: &Point,
    value: u64,
    blinding: &BigUint,
    bits: usize,
    context: &[u8],
) -> HarnessResult<RangeProof> {
    if bits < 64 && value >= (1u64 << bits) {
        return Err(format!("value {value} outside [0, 2^{bits})").into());
    }
    let bit_values: Vec<usize> = (0..bits).map(|bit| ((value >> bit) & 1) as usize).collect();
    let bit_blindings: Vec<BigUint> = (0..bits).map(|_| key.group.random_scalar()).collect();
    let bit_commitments: Vec<Point> = bit_values
        .iter()
        .zip(&bit_blindings)
        .map(|(&value, blinding)| key.commit(&BigUint::from(value), blinding))
        .collect();
    let bit_proofs: Vec<BitProof> = (0..bits)
        .map(|bit| {
            let mut suffix = b":bit:".to_vec();
            suffix.extend_from_slice(&(bit as u16).to_be_bytes());
            prove_bit(
                key,
                &bit_commitments[bit],
                bit_values[bit],
                &bit_blindings[bit],
                &context_suffix(context, &suffix),
            )
        })
        .collect();
    let mut combined_blinding = BigUint::zero();
    let mut aggregate = key.group.identity();
    for bit in 0..bits {
        let weight = BigUint::one() << bit;
        combined_blinding += &weight * &bit_blindings[bit];
        aggregate = key.group.mul(
            &aggregate,
            &key.group.point_pow(&bit_commitments[bit], &weight),
        );
    }
    combined_blinding %= key.group.order();
    let residual_blinding = mod_sub(blinding, &combined_blinding, key.group.order());
    let residual = key.group.mul(commitment, &key.group.neg(&aggregate));
    let linkage = prove_opening(
        key,
        &residual,
        &BigUint::zero(),
        &residual_blinding,
        &context_suffix(context, b":link"),
    );
    Ok(RangeProof {
        bit_commitments,
        bit_proofs,
        linkage,
        bits,
    })
}

fn verify_range(key: &Pedersen, commitment: &Point, proof: &RangeProof, context: &[u8]) -> bool {
    if proof.bit_commitments.len() != proof.bits || proof.bit_proofs.len() != proof.bits {
        return false;
    }
    for bit in 0..proof.bits {
        let mut suffix = b":bit:".to_vec();
        suffix.extend_from_slice(&(bit as u16).to_be_bytes());
        if !key.group.is_valid(&proof.bit_commitments[bit])
            || !verify_bit(
                key,
                &proof.bit_commitments[bit],
                &proof.bit_proofs[bit],
                &context_suffix(context, &suffix),
            )
        {
            return false;
        }
    }
    let mut aggregate = key.group.identity();
    for (bit, commitment) in proof.bit_commitments.iter().enumerate() {
        aggregate = key.group.mul(
            &aggregate,
            &key.group.point_pow(commitment, &(BigUint::one() << bit)),
        );
    }
    let residual = key.group.mul(commitment, &key.group.neg(&aggregate));
    verify_opening(
        key,
        &residual,
        &proof.linkage,
        &context_suffix(context, b":link"),
    )
}

fn signed_scalar(value: i64, order: &BigUint) -> BigUint {
    if value >= 0 {
        BigUint::from(value as u64) % order
    } else {
        let magnitude = BigUint::from(value.unsigned_abs()) % order;
        if magnitude.is_zero() {
            magnitude
        } else {
            order - magnitude
        }
    }
}

fn shift_commitment(key: &Pedersen, commitment: &Point, low: i64) -> Point {
    key.group.mul(
        commitment,
        &key.group.neg(
            &key.group
                .point_pow(&key.g, &signed_scalar(low, key.group.order())),
        ),
    )
}

fn span_bits(low: i64, high: i64) -> HarnessResult<usize> {
    let span = high.checked_sub(low).ok_or("empty interval")?;
    if span < 0 {
        return Err("empty interval".into());
    }
    Ok((64 - (span as u64).leading_zeros()).max(1) as usize)
}

fn prove_bounded(
    key: &Pedersen,
    value: i64,
    blinding: &BigUint,
    low: i64,
    high: i64,
    context: &[u8],
) -> HarnessResult<(Point, BoundedProof)> {
    if value < low || value > high {
        return Err(format!("value {value} outside [{low}, {high}]").into());
    }
    let bits = span_bits(low, high)?;
    let commitment = key.commit(&signed_scalar(value, key.group.order()), blinding);
    let above = prove_range(
        key,
        &shift_commitment(key, &commitment, low),
        (value - low) as u64,
        blinding,
        bits,
        &context_suffix(context, b"|above"),
    )?;
    let ceiling = key.commit(&signed_scalar(high, key.group.order()), &BigUint::zero());
    let below_commitment = key.group.mul(
        &ceiling,
        &key.group
            .point_pow(&commitment, &(key.group.order() - BigUint::one())),
    );
    let below_blinding = mod_sub(&BigUint::zero(), blinding, key.group.order());
    let below = prove_range(
        key,
        &below_commitment,
        (high - value) as u64,
        &below_blinding,
        bits,
        &context_suffix(context, b"|below"),
    )?;
    Ok((commitment, BoundedProof { above, below, bits }))
}

fn verify_bounded(
    key: &Pedersen,
    commitment: &Point,
    proof: &BoundedProof,
    low: i64,
    high: i64,
    context: &[u8],
) -> bool {
    let Ok(bits) = span_bits(low, high) else {
        return false;
    };
    if proof.bits != bits
        || proof.above.bits != bits
        || proof.below.bits != bits
        || !key.group.is_valid(commitment)
        || !verify_range(
            key,
            &shift_commitment(key, commitment, low),
            &proof.above,
            &context_suffix(context, b"|above"),
        )
    {
        return false;
    }
    let ceiling = key.commit(&signed_scalar(high, key.group.order()), &BigUint::zero());
    let below_commitment = key.group.mul(
        &ceiling,
        &key.group
            .point_pow(commitment, &(key.group.order() - BigUint::one())),
    );
    verify_range(
        key,
        &below_commitment,
        &proof.below,
        &context_suffix(context, b"|below"),
    )
}

const POLICY_FIELDS: [&str; 6] = ["ask_level", "spread", "slope", "invcoef", "inv", "maxqty"];

fn policy_bound(name: &str, ref_mid: i64) -> (i64, i64) {
    match name {
        "ask_level" => (ref_mid - 2_000, ref_mid + 2_000),
        "spread" => (2, 400),
        "slope" => (0, 16),
        "invcoef" => (0, 8),
        "maxqty" => (1, 1_000),
        "inv" => (-4_000, 4_000),
        _ => panic!("unknown policy field {name}"),
    }
}

#[derive(Clone)]
struct PolicyShare {
    party: u64,
    value_share: BigUint,
    blinding_share: BigUint,
}

#[derive(Clone)]
struct FieldCommitment {
    commitment: Point,
    coefficients: Vec<Point>,
}

#[derive(Clone)]
struct PolicyAudit {
    ref_mid: i64,
    now_t: i64,
    expiry: i64,
    fields: BTreeMap<String, FieldCommitment>,
    range_proofs: BTreeMap<String, BoundedProof>,
    active_commitment: Point,
    active_proof: BitProof,
    entity_nullifier: Point,
}

#[derive(Clone)]
struct PolicyCommitter {
    group: Group,
    key: Pedersen,
}

impl PolicyCommitter {
    fn new(group: Group) -> Self {
        Self {
            group,
            key: Pedersen::new(group, b"qomm:policy:v1"),
        }
    }

    fn share(
        &self,
        value: i64,
        blinding: &BigUint,
        n_parties: u64,
        threshold: usize,
    ) -> (FieldCommitment, Vec<PolicyShare>) {
        let mut value_poly = vec![signed_scalar(value, self.group.order())];
        let mut blind_poly = vec![blinding.clone() % self.group.order()];
        value_poly.extend((0..threshold).map(|_| self.group.random_scalar()));
        blind_poly.extend((0..threshold).map(|_| self.group.random_scalar()));
        let coefficients: Vec<Point> = value_poly
            .iter()
            .zip(&blind_poly)
            .map(|(value, blind)| self.key.commit(value, blind))
            .collect();
        let shares = (1..=n_parties)
            .map(|party| {
                let x = BigUint::from(party);
                let mut power = BigUint::one();
                let mut value_share = BigUint::zero();
                let mut blinding_share = BigUint::zero();
                for degree in 0..=threshold {
                    value_share += &value_poly[degree] * &power;
                    blinding_share += &blind_poly[degree] * &power;
                    power = (power * &x) % self.group.order();
                }
                PolicyShare {
                    party,
                    value_share: value_share % self.group.order(),
                    blinding_share: blinding_share % self.group.order(),
                }
            })
            .collect();
        (
            FieldCommitment {
                commitment: coefficients[0].clone(),
                coefficients,
            },
            shares,
        )
    }

    fn verify_share(&self, share: &PolicyShare, commitment: &FieldCommitment) -> bool {
        let x = BigUint::from(share.party);
        let mut power = BigUint::one();
        let mut expected = self.group.identity();
        for coefficient in &commitment.coefficients {
            expected = self
                .group
                .mul(&expected, &self.group.point_pow(coefficient, &power));
            power = (power * &x) % self.group.order();
        }
        let actual = self.key.commit(&share.value_share, &share.blinding_share);
        self.group.equal(&actual, &expected)
    }

    fn context(&self, ref_mid: i64, now_t: i64, expiry: i64, nullifier: &Point) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(b":policy-ctx:");
        for value in [ref_mid, now_t, expiry] {
            digest.update(i128::from(value).to_be_bytes());
        }
        digest.update(self.group.encode(nullifier));
        digest.finalize().to_vec()
    }

    fn audit(
        &self,
        policy: &BTreeMap<&'static str, i64>,
        ref_mid: i64,
        now_t: i64,
        n_parties: u64,
        threshold: usize,
        entity_nullifier: &Point,
    ) -> HarnessResult<(PolicyAudit, BTreeMap<String, Vec<PolicyShare>>)> {
        let expiry = *policy.get("expiry").ok_or("policy has no expiry")?;
        let context = self.context(ref_mid, now_t, expiry, entity_nullifier);
        let mut fields = BTreeMap::new();
        let mut range_proofs = BTreeMap::new();
        let mut all_shares = BTreeMap::new();
        for name in POLICY_FIELDS {
            let value = *policy
                .get(name)
                .ok_or_else(|| format!("policy has no {name}"))?;
            let (low, high) = policy_bound(name, ref_mid);
            let blinding = self.group.random_scalar();
            let field_context = context_suffix(&context, format!(":{name}").as_bytes());
            let (commitment, proof) =
                prove_bounded(&self.key, value, &blinding, low, high, &field_context)?;
            let (field, shares) = self.share(value, &blinding, n_parties, threshold);
            if !self.group.equal(&commitment, &field.commitment) {
                return Err(format!("{name}: range and VSS commitments differ").into());
            }
            fields.insert(name.to_string(), field);
            range_proofs.insert(name.to_string(), proof);
            all_shares.insert(name.to_string(), shares);
        }
        let active = *policy.get("active").ok_or("policy has no active flag")?;
        if !(0..=1).contains(&active) {
            return Err("active flag is not a bit".into());
        }
        let active_blinding = self.group.random_scalar();
        let active_commitment = self
            .key
            .commit(&BigUint::from(active as u64), &active_blinding);
        let active_proof = prove_bit(
            &self.key,
            &active_commitment,
            active as usize,
            &active_blinding,
            &context_suffix(&context, b":active"),
        );
        Ok((
            PolicyAudit {
                ref_mid,
                now_t,
                expiry,
                fields,
                range_proofs,
                active_commitment,
                active_proof,
                entity_nullifier: entity_nullifier.clone(),
            },
            all_shares,
        ))
    }

    fn verify(&self, audit: &PolicyAudit, now_t: i64, ref_mid: i64, max_horizon: i64) -> bool {
        if audit.ref_mid != ref_mid
            || audit.now_t != now_t
            || audit.expiry <= now_t
            || audit.expiry > now_t + max_horizon
        {
            return false;
        }
        let context = self.context(ref_mid, now_t, audit.expiry, &audit.entity_nullifier);
        for name in POLICY_FIELDS {
            let (Some(field), Some(proof)) = (audit.fields.get(name), audit.range_proofs.get(name))
            else {
                return false;
            };
            if field.coefficients.is_empty()
                || !self.group.equal(&field.commitment, &field.coefficients[0])
            {
                return false;
            }
            let (low, high) = policy_bound(name, ref_mid);
            if !verify_bounded(
                &self.key,
                &field.commitment,
                proof,
                low,
                high,
                &context_suffix(&context, format!(":{name}").as_bytes()),
            ) {
                return false;
            }
        }
        verify_bit(
            &self.key,
            &audit.active_commitment,
            &audit.active_proof,
            &context_suffix(&context, b":active"),
        )
    }
}

#[derive(Clone)]
struct KybCredential {
    control_group_id: String,
    secret: BigUint,
    public_point: Point,
}

#[derive(Clone)]
struct CohortRegistry {
    cohort: String,
    registry_epoch: u64,
    expires_at: u64,
    points: Vec<Point>,
    registry_id: String,
    body: Vec<u8>,
    signature: ed25519_dalek::Signature,
    issuer: VerifyingKey,
}

#[derive(Clone)]
struct KybPresentation {
    cohort: String,
    registry_id: String,
    scope: String,
    context_hash: String,
    proof: OrProof,
}

struct KybIssuer {
    group: Group,
    signing: SigningKey,
    enrolled: Vec<KybCredential>,
}

impl KybIssuer {
    fn new(group: Group) -> Self {
        Self {
            group,
            signing: SigningKey::generate(&mut OsRng),
            enrolled: Vec::new(),
        }
    }

    fn enroll(&mut self, control_group_id: String) -> HarnessResult<KybCredential> {
        if self
            .enrolled
            .iter()
            .any(|credential| credential.control_group_id == control_group_id)
        {
            return Err(format!("control group {control_group_id} already enrolled").into());
        }
        let secret = self.group.random_scalar();
        let credential = KybCredential {
            control_group_id,
            public_point: self.group.base_pow(&secret),
            secret,
        };
        self.enrolled.push(credential.clone());
        Ok(credential)
    }

    fn publish(
        &self,
        cohort: &str,
        registry_epoch: u64,
        expires_at: u64,
    ) -> HarnessResult<CohortRegistry> {
        if self.enrolled.is_empty() {
            return Err(format!("no entity qualifies for {cohort}").into());
        }
        let mut points: Vec<Point> = self
            .enrolled
            .iter()
            .map(|credential| credential.public_point.clone())
            .collect();
        points.sort_by_key(|point| self.group.encode(point));
        let issuer = self.signing.verifying_key();
        let mut body = Vec::new();
        body.extend_from_slice(cohort.as_bytes());
        body.extend_from_slice(&registry_epoch.to_be_bytes());
        body.extend_from_slice(&expires_at.to_be_bytes());
        body.extend_from_slice(issuer.as_bytes());
        for point in &points {
            let encoded = self.group.encode(point);
            body.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            body.extend_from_slice(&encoded);
        }
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(b":kyb-registry:");
        digest.update(&body);
        let registry_id = hex::encode(digest.finalize());
        let mut signed = body.clone();
        signed.extend_from_slice(registry_id.as_bytes());
        let signature = self.signing.sign(&signed);
        Ok(CohortRegistry {
            cohort: cohort.to_string(),
            registry_epoch,
            expires_at,
            points,
            registry_id,
            body,
            signature,
            issuer,
        })
    }
}

fn verify_registry(registry: &CohortRegistry, trusted: &VerifyingKey, now: u64) -> bool {
    if registry.issuer != *trusted || registry.expires_at <= now || registry.registry_epoch == 0 {
        return false;
    }
    let mut unique: Vec<Vec<u8>> = registry
        .points
        .iter()
        .map(|point| match point {
            Point::Modp(point) => point.to_bytes_be(),
            Point::Ed25519(point) => point.compress().to_bytes().to_vec(),
        })
        .collect();
    unique.sort();
    unique.dedup();
    if unique.len() != registry.points.len() {
        return false;
    }
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(b":kyb-registry:");
    digest.update(&registry.body);
    if hex::encode(digest.finalize()) != registry.registry_id {
        return false;
    }
    let mut signed = registry.body.clone();
    signed.extend_from_slice(registry.registry_id.as_bytes());
    trusted.verify(&signed, &registry.signature).is_ok()
}

fn kyb_context_hash() -> String {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(b":kyb-context:");
    digest.update(b"{\"asset\":1,\"venue\":\"qomm\"}");
    hex::encode(digest.finalize())
}

fn present(
    group: Group,
    credential: &KybCredential,
    registry: &CohortRegistry,
    scope: &str,
) -> HarnessResult<KybPresentation> {
    let encoded = group.encode(&credential.public_point);
    let index = registry
        .points
        .iter()
        .position(|point| group.encode(point) == encoded)
        .ok_or("credential is not in this registry")?;
    let context_hash = kyb_context_hash();
    let statement = Statement {
        registry_id: registry.registry_id.clone(),
        points: registry.points.clone(),
        scope: scope.to_string(),
        context_hash: context_hash.clone(),
    };
    Ok(KybPresentation {
        cohort: registry.cohort.clone(),
        registry_id: registry.registry_id.clone(),
        scope: scope.to_string(),
        context_hash,
        proof: or_prove(group, &statement, &credential.secret, index)?,
    })
}

fn verify_presentation(
    group: Group,
    presentation: &KybPresentation,
    registry: &CohortRegistry,
    trusted: &VerifyingKey,
    scope: &str,
    now: u64,
    required_cohort: &str,
) -> bool {
    if !verify_registry(registry, trusted, now)
        || registry.cohort != required_cohort
        || presentation.cohort != required_cohort
        || presentation.registry_id != registry.registry_id
        || presentation.scope != scope
        || presentation.context_hash != kyb_context_hash()
    {
        return false;
    }
    let statement = Statement {
        registry_id: registry.registry_id.clone(),
        points: registry.points.clone(),
        scope: scope.to_string(),
        context_hash: presentation.context_hash.clone(),
    };
    or_verify(group, &statement, &presentation.proof)
}

fn scope_nullifier(group: Group, credential: &KybCredential, scope: &str) -> Point {
    group.point_pow(&group.hash_to_point(scope.as_bytes()), &credential.secret)
}

fn timed(mut operation: impl FnMut(), repeats: usize) -> Value {
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let started = Instant::now();
        operation();
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    let mut ordered = samples.clone();
    ordered.sort_by(f64::total_cmp);
    let p95 = ordered[((0.95 * ordered.len() as f64) as usize).min(ordered.len() - 1)];
    let mut summary = timing_summary(&samples);
    summary
        .as_object_mut()
        .expect("timing_summary returns an object")
        .insert("p95".into(), json!(p95));
    summary
}

pub fn primitive_costs() -> Value {
    let group = Group::new("modp_multiexp").expect("the built-in group exists");
    let scalar = group.random_scalar_with(&mut OsRng, true);
    let point = group.base_pow(&group.random_scalar_with(&mut OsRng, true));
    let Point::Modp(point_value) = &point else {
        unreachable!()
    };
    let mut out = Map::new();
    out.insert(
        "modp_fixed_base_exp".into(),
        timed(
            || {
                black_box(BigUint::from(2u8).modpow(&scalar, modp_p()));
            },
            20,
        ),
    );
    out.insert(
        "modp_var_base_exp".into(),
        timed(
            || {
                black_box(point_value.modpow(&scalar, modp_p()));
            },
            20,
        ),
    );
    out.insert(
        "modp_inverse_fermat".into(),
        timed(
            || {
                black_box(point_value.modpow(&(modp_p() - BigUint::from(2u8)), modp_p()));
            },
            20,
        ),
    );
    out.insert(
        "modp_inverse_euclid".into(),
        timed(
            || {
                black_box(mod_inverse(point_value, modp_p()));
            },
            500,
        ),
    );
    out.insert(
        "modp_mul".into(),
        timed(
            || {
                black_box((point_value * point_value) % modp_p());
            },
            5_000,
        ),
    );
    let ed = Group::new("ed25519").expect("the built-in group exists");
    let ed_point = ed.base_pow(&BigUint::from(12_345u64));
    out.insert(
        "ed25519_fixed_base_mul".into(),
        timed(
            || {
                black_box(ed.base_pow(&scalar));
            },
            500,
        ),
    );
    out.insert(
        "ed25519_var_base_mul".into(),
        timed(
            || {
                black_box(ed.point_pow(&ed_point, &scalar));
            },
            500,
        ),
    );
    out.insert(
        "ed25519_hash_to_point".into(),
        timed(
            || {
                black_box(ed.hash_to_point(b"scope"));
            },
            200,
        ),
    );
    Value::Object(out)
}

pub fn ladder_row(name: &str, size: usize, repeats: usize) -> HarnessResult<Value> {
    let group = Group::new(name)?;
    let (statement, secrets) = build_registry(group, size, 7);
    let index = size / 2;
    let secret = &secrets[index];
    let proof = or_prove(group, &statement, secret, index)?;
    if !or_verify(group, &statement, &proof) {
        return Ok(json!({"backend": name, "size": size, "error": "verify failed"}));
    }
    Ok(json!({
        "backend": name,
        "registry_size": size,
        "security_bits": group.security_bits(),
        "proof_bytes": proof.size_bytes(group),
        "prove": timed(|| { black_box(or_prove(group, &statement, secret, index).expect("valid fixture")); }, repeats),
        "verify": timed(|| { black_box(or_verify(group, &statement, &proof)); }, repeats),
    }))
}

pub fn application_rows(name: &str) -> HarnessResult<Vec<Value>> {
    let group = Group::new(name)?;
    let repeats = if name == "ed25519" { 50 } else { 3 };
    let committer = PolicyCommitter::new(group);
    let nullifier = group.hash_to_point(b"entity");
    let policy = BTreeMap::from([
        ("ask_level", 100_000),
        ("spread", 28),
        ("slope", 2),
        ("invcoef", 1),
        ("inv", -320),
        ("maxqty", 400),
        ("expiry", 1_600),
        ("active", 1),
    ]);
    let (audit, shares) = committer.audit(&policy, 100_000, 1_000, 7, 2, &nullifier)?;
    if !committer.verify(&audit, 1_000, 100_000, 3_600) {
        return Err(format!("{name}: policy audit fixture did not verify").into());
    }
    let mut rows = vec![json!({
        "proof": "market_maker_policy_audit",
        "backend": name,
        "fields_audited": audit.fields.len() + 1,
        "parties": 7,
        "prove": timed(|| {
            black_box(committer.audit(&policy, 100_000, 1_000, 7, 2, &nullifier).expect("valid policy"));
        }, repeats),
        "verify": timed(|| {
            black_box(committer.verify(&audit, 1_000, 100_000, 3_600));
        }, repeats),
        "share_check_all_nodes": timed(|| {
            let valid = shares.iter().all(|(field, values)| {
                let commitment = &audit.fields[field];
                values.iter().all(|share| committer.verify_share(share, commitment))
            });
            black_box(valid);
        }, repeats),
    })];

    for cohort_size in [8usize, 64] {
        let mut issuer = KybIssuer::new(group);
        let mut credential = None;
        for index in 0..cohort_size {
            let enrolled = issuer.enroll(format!("GROUP-{index}"))?;
            if index == 0 {
                credential = Some(enrolled);
            }
        }
        let credential = credential.expect("cohort is non-empty");
        let cohort = "JP/bank/tier>=2";
        let registry = issuer.publish(cohort, 1, 9_999)?;
        let presentation = present(group, &credential, &registry, "qomm:quote:epoch7")?;
        if !verify_presentation(
            group,
            &presentation,
            &registry,
            &issuer.signing.verifying_key(),
            "qomm:quote:epoch7",
            100,
            cohort,
        ) {
            return Err(format!("{name}: KYB presentation fixture did not verify").into());
        }
        rows.push(json!({
            "proof": "kyb_cohort_presentation",
            "backend": name,
            "cohort_size": cohort_size,
            "prove": timed(|| {
                black_box(present(group, &credential, &registry, "qomm:quote:epoch7").expect("valid credential"));
            }, repeats),
            "verify": timed(|| {
                black_box(verify_presentation(
                    group,
                    &presentation,
                    &registry,
                    &issuer.signing.verifying_key(),
                    "qomm:quote:epoch7",
                    100,
                    cohort,
                ));
            }, repeats),
            "nullifier": timed(|| {
                black_box(scope_nullifier(group, &credential, "qomm:quote:epoch7"));
            }, repeats),
        }));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_backend_proves_the_same_statement_shape() {
        for name in BACKENDS {
            let group = Group::new(name).unwrap();
            let (statement, secrets) = build_registry(group, 4, 7);
            let proof = or_prove(group, &statement, &secrets[2], 2).unwrap();
            assert!(or_verify(group, &statement, &proof), "{name}");
            let point_bytes = if name == "ed25519" { 32 } else { 256 };
            assert_eq!(proof.size_bytes(group), point_bytes + 8 * point_bytes);
        }
    }

    #[test]
    fn policy_and_kyb_fixtures_verify() {
        let group = Group::new("ed25519").unwrap();
        let committer = PolicyCommitter::new(group);
        let nullifier = group.hash_to_point(b"entity");
        let policy = BTreeMap::from([
            ("ask_level", 100_000),
            ("spread", 28),
            ("slope", 2),
            ("invcoef", 1),
            ("inv", -320),
            ("maxqty", 400),
            ("expiry", 1_600),
            ("active", 1),
        ]);
        let (audit, shares) = committer
            .audit(&policy, 100_000, 1_000, 7, 2, &nullifier)
            .unwrap();
        assert!(committer.verify(&audit, 1_000, 100_000, 3_600));
        assert!(shares.iter().all(|(field, values)| values
            .iter()
            .all(|share| committer.verify_share(share, &audit.fields[field]))));

        let mut issuer = KybIssuer::new(group);
        let credential = issuer.enroll("GROUP-0".into()).unwrap();
        issuer.enroll("GROUP-1".into()).unwrap();
        let registry = issuer.publish("JP/bank/tier>=2", 1, 9_999).unwrap();
        let presentation = present(group, &credential, &registry, "qomm:quote:epoch7").unwrap();
        assert!(verify_presentation(
            group,
            &presentation,
            &registry,
            &issuer.signing.verifying_key(),
            "qomm:quote:epoch7",
            100,
            "JP/bank/tier>=2",
        ));
    }
}
