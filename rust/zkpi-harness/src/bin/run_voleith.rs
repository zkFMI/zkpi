use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use zkpi_harness::voleith::{self, Packing, COMMIT_BYTES, SEED_BYTES};
use zkpi_harness::{parse_value, timing_summary, write_pretty_json, HarnessResult};
use zkfmi_zk::pedersen::Pedersen;
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha512};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

const VALUE_BITS: usize = 31;
const MASK_BITS: usize = 119;
const PEDERSEN_DOMAIN: &[u8] = b"QOMM:ZK:v1";
const PEDERSEN_CHALLENGE: u64 = 0x9E37_79B9_7F4A_7C15;

struct Options {
    inputs: Vec<usize>,
    repeats: usize,
    depth: usize,
    tree_repeats: usize,
    phases: bool,
    out: PathBuf,
    arithmetic_only: bool,
}

struct PedersenProof {
    commitments: Vec<RistrettoPoint>,
    mask_commitment: RistrettoPoint,
    opening: Scalar,
    opening_blinding: Scalar,
}

fn main() {
    match run_main() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run_main() -> HarnessResult<bool> {
    let options = parse_args()?;
    let max_inputs = *options
        .inputs
        .iter()
        .max()
        .ok_or("--inputs expects at least one value")?;
    if options.depth == 0
        || options.tree_repeats == 0
        || options.repeats == 0
        || options.depth >= 63
    {
        return Err(
            "depth/tree-repeats/repeats must be positive and depth must be below 63".into(),
        );
    }
    if options.arithmetic_only {
        if !options.out.exists() {
            eprintln!(
                "{} does not exist; run without --arithmetic-only",
                options.out.display()
            );
            return Ok(false);
        }
        let mut held: Value = serde_json::from_slice(&fs::read(&options.out)?)?;
        held["sweep"] = parameter_sweep(max_inputs);
        held["linear_code"] = linear_code_arithmetic(max_inputs, options.depth);
        write_pretty_json(Some(&options.out), &held)?;
        let best = &held["linear_code"]["protocol_complete"];
        println!(
            "recomputed the arithmetic in {}, timings untouched (measured on {})",
            options.out.display(),
            zkpi_harness::value_display(&held["host"]),
        );
        println!(
            "  Pi_2D-LC best: k_C={} n_C={} {} B, {} hashes",
            best["k_C"], best["n_C"], best["bytes"], best["hashes"]
        );
        return Ok(true);
    }

    let mut rng = OsRng;
    let mut pedersen_rows = Vec::new();
    let mut voleith_rows = Vec::new();
    for &count in &options.inputs {
        if count == 0 {
            return Err("an input check over no inputs checks nothing".into());
        }
        let values = sample(count, &mut rng);
        let context = format!("qomm:voleith-bench:{count}").into_bytes();
        let pedersen = time_pedersen(&values, &context, options.repeats, &mut rng)?;
        print_arm("pedersen", count, &pedersen);
        pedersen_rows.push(pedersen);
        let vole = time_voleith(
            &values,
            &context,
            options.repeats,
            options.depth,
            options.tree_repeats,
            &mut rng,
        )?;
        print_arm("voleith", count, &vole);
        voleith_rows.push(vole);
    }
    let mut ratios = Map::new();
    for (index, &count) in options.inputs.iter().enumerate() {
        let ped = &pedersen_rows[index];
        let vol = &voleith_rows[index];
        ratios.insert(count.to_string(), json!({
            "prove": round_places(vol["prove_ms"]["median"].as_f64().unwrap_or(0.0) / ped["prove_ms"]["median"].as_f64().unwrap_or(1.0), 2),
            "verify": round_places(vol["verify_ms"]["median"].as_f64().unwrap_or(0.0) / ped["verify_ms"]["median"].as_f64().unwrap_or(1.0), 2),
            "bytes": round_places(vol["bytes"]["exact"].as_f64().unwrap_or(0.0) / ped["bytes"]["exact"].as_f64().unwrap_or(1.0), 2),
        }));
    }
    let mut result = json!({
        "host": zkfmi_measure::hosts::this_host(),
        "repeats": options.repeats,
        "modulus_bits": 127,
        "depth": options.depth,
        "tree_repeats": options.tree_repeats,
        "soundness_bits": options.depth * options.tree_repeats,
        // Both arms now share the same language and measurement harness.
        "caveat": "Both arms are Rust. Pedersen uses curve25519-dalek; VOLEitH uses the sha2 and sha3 crates over this repository's own field arithmetic. The curve backend is audited and heavily tuned while the field arithmetic is not, so part of the timing ratio remains an implementation comparison. Bytes and hash counts do not have this problem.",
        "arms": {"pedersen": pedersen_rows, "voleith": voleith_rows},
        "ratios": ratios,
        "sweep": parameter_sweep(max_inputs),
        "linear_code": linear_code_arithmetic(max_inputs, options.depth),
    });
    if options.phases {
        result["phases"] = phase_split(
            max_inputs,
            options.depth,
            options.tree_repeats,
            3usize.max(options.repeats / 6),
            &mut rng,
        );
    }
    println!("\nVOLEitH over Pedersen, same statement, both publicly verifiable:");
    for &count in &options.inputs {
        let row = &result["ratios"][count.to_string()];
        println!(
            "  {count:5} inputs  prove {:>6.2}x  verify {:>6.2}x  bytes {:>6.2}x",
            row["prove"].as_f64().unwrap_or(0.0),
            row["verify"].as_f64().unwrap_or(0.0),
            row["bytes"].as_f64().unwrap_or(0.0),
        );
    }
    write_pretty_json(Some(&options.out), &result)?;
    println!("\nwrote {}", options.out.display());
    let accepted = result["arms"]
        .as_object()
        .into_iter()
        .flat_map(|arms| arms.values())
        .flat_map(|rows| rows.as_array().into_iter().flatten())
        .all(|row| row["accepted"] == true);
    Ok(accepted)
}

fn sample(count: usize, rng: &mut OsRng) -> Vec<u128> {
    (0..count)
        .map(|index| {
            random_bits(
                if index + 1 == count {
                    MASK_BITS
                } else {
                    VALUE_BITS
                },
                rng,
            )
        })
        .collect()
}

fn time_pedersen(
    values: &[u128],
    context: &[u8],
    repeats: usize,
    rng: &mut OsRng,
) -> HarnessResult<Value> {
    let key = Pedersen::new(b"qomm:pedersen:v1");
    let first = prove_pedersen(&key, values, context, rng);
    let (accepted, why) = verify_pedersen(&key, &first, context);
    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    for _ in 0..repeats {
        let started = Instant::now();
        let proof = prove_pedersen(&key, values, context, rng);
        prove_ms.push(started.elapsed().as_secs_f64() * 1e3);
        let started = Instant::now();
        std::hint::black_box(verify_pedersen(&key, &proof, context));
        verify_ms.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let size = pedersen_size(values.len());
    Ok(json!({
        "accepted": accepted,
        "why": why,
        "prove_ms": timing_summary(&prove_ms),
        "verify_ms": timing_summary(&verify_ms),
        "bytes": {
            "exact": size.values().filter_map(Value::as_u64).sum::<u64>()
        },
        "size_breakdown": size,
        "n_inputs": values.len(),
    }))
}

fn prove_pedersen(
    key: &Pedersen,
    values: &[u128],
    context: &[u8],
    rng: &mut OsRng,
) -> PedersenProof {
    let blindings = (0..values.len())
        .map(|_| Scalar::random(&mut *rng))
        .collect::<Vec<_>>();
    let commitments = values
        .iter()
        .zip(&blindings)
        .map(|(&value, blinding)| key.commit(&scalar(value), blinding))
        .collect::<Vec<_>>();
    let mask = random_bits(mask_bits(values.len(), VALUE_BITS), rng);
    let mask_blinding = Scalar::random(&mut *rng);
    let mask_commitment = key.commit(&scalar(mask), &mask_blinding);
    let coefficients = pedersen_coefficients(&commitments, &mask_commitment, context);
    let opening = values
        .iter()
        .zip(&coefficients)
        .fold(scalar(mask), |sum, (&value, &coefficient)| {
            sum + scalar(value) * Scalar::from(coefficient)
        });
    let opening_blinding = blindings
        .iter()
        .zip(&coefficients)
        .fold(mask_blinding, |sum, (blinding, &coefficient)| {
            sum + blinding * Scalar::from(coefficient)
        });
    PedersenProof {
        commitments,
        mask_commitment,
        opening,
        opening_blinding,
    }
}

fn verify_pedersen(key: &Pedersen, proof: &PedersenProof, context: &[u8]) -> (bool, String) {
    let coefficients = pedersen_coefficients(&proof.commitments, &proof.mask_commitment, context);
    let combined = proof
        .commitments
        .iter()
        .zip(coefficients)
        .fold(proof.mask_commitment, |sum, (commitment, coefficient)| {
            sum + commitment * Scalar::from(coefficient)
        });
    if key.commit(&proof.opening, &proof.opening_blinding) == combined {
        (true, "ok".into())
    } else {
        (false, "combination 0 is not what the committed inputs combine to: an input the circuit used was not the one that was committed".into())
    }
}

fn pedersen_coefficients(
    commitments: &[RistrettoPoint],
    mask: &RistrettoPoint,
    context: &[u8],
) -> Vec<u64> {
    let mut seed = Sha512::new();
    seed.update(PEDERSEN_DOMAIN);
    seed.update(b":input-check:v1");
    seed.update((context.len() as u32).to_be_bytes());
    seed.update(context);
    seed.update((commitments.len() as u32).to_be_bytes());
    for commitment in commitments {
        let encoded = commitment.compress().to_bytes();
        seed.update((encoded.len() as u32).to_be_bytes());
        seed.update(encoded);
    }
    let encoded = mask.compress().to_bytes();
    seed.update((encoded.len() as u32).to_be_bytes());
    seed.update(encoded);
    seed.update(0u32.to_be_bytes());
    let mut challenge = [0u8; 32];
    challenge[24..].copy_from_slice(&PEDERSEN_CHALLENGE.to_be_bytes());
    seed.update(challenge);
    let root = seed.finalize();
    let modulus = (1u64 << 40) - 1;
    (0..commitments.len())
        .map(|index| {
            let mut hash = Sha512::new();
            hash.update(root);
            hash.update((index as u32).to_be_bytes());
            1 + hash.finalize().iter().fold(0u64, |value, byte| {
                ((value as u128 * 256 + *byte as u128) % modulus as u128) as u64
            })
        })
        .collect()
}

fn pedersen_size(inputs: usize) -> Map<String, Value> {
    [
        ("commitments", inputs * 32),
        ("mask_commitments", 32),
        ("openings", 32),
        ("opening_blindings", 32),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), json!(value)))
    .collect()
}

fn time_voleith(
    values: &[u128],
    context: &[u8],
    repeats: usize,
    depth: usize,
    tree_repeats: usize,
    rng: &mut OsRng,
) -> HarnessResult<Value> {
    let first = voleith::prove(values, context, depth, tree_repeats, rng)?;
    let (accepted, why) = voleith::verify(&first, context);
    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut proof = first;
    for _ in 0..repeats {
        let started = Instant::now();
        proof = voleith::prove(values, context, depth, tree_repeats, rng)?;
        prove_ms.push(started.elapsed().as_secs_f64() * 1e3);
        let started = Instant::now();
        std::hint::black_box(voleith::verify(&proof, context));
        verify_ms.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let size = proof
        .size_breakdown()
        .into_iter()
        .map(|(key, value)| (key.to_string(), json!(value)))
        .collect::<Map<_, _>>();
    Ok(json!({
        "accepted": accepted,
        "why": why,
        "prove_ms": timing_summary(&prove_ms),
        "verify_ms": timing_summary(&verify_ms),
        "bytes": {"exact": proof.size_bytes()},
        "size_breakdown": size,
        "n_inputs": values.len(),
    }))
}

fn phase_split(n: usize, depth: usize, repeats: usize, rounds: usize, rng: &mut OsRng) -> Value {
    let packing = Packing { length: n, depth };
    let mut seeds = vec![[0u8; SEED_BYTES]; 1usize << depth];
    for seed in &mut seeds {
        rng.fill_bytes(seed);
    }
    let leaves = repeats * (1usize << depth);
    let mut xof = Vec::new();
    for _ in 0..rounds {
        let started = Instant::now();
        for _ in 0..repeats {
            for (index, seed) in seeds.iter().enumerate() {
                let mut input = seed.to_vec();
                input.extend_from_slice(&(index as u32).to_be_bytes());
                std::hint::black_box(voleith::shake_raw(&input, packing.blob_bytes()));
            }
        }
        xof.push(started.elapsed().as_secs_f64() * 1e3);
    }
    let mut both = Vec::new();
    for _ in 0..rounds {
        let started = Instant::now();
        for _ in 0..repeats {
            let mut sums = vec![0u128; n];
            let mut weighted = vec![0u128; n];
            for (index, seed) in seeds.iter().enumerate() {
                let values = packing.leaf(seed, 0, index);
                for position in 0..n {
                    sums[position] = voleith::add_mod(sums[position], values[position]);
                    weighted[position] = voleith::add_mod(
                        weighted[position],
                        voleith::mul_mod(index as u128, values[position]),
                    );
                }
            }
            std::hint::black_box((&sums, &weighted));
        }
        both.push(started.elapsed().as_secs_f64() * 1e3);
    }
    json!({
        "leaves": {"exact": leaves},
        "prg_bytes": {"exact": leaves * packing.blob_bytes()},
        "xof_only_ms": timing_summary(&xof),
        "xof_and_packing_ms": timing_summary(&both),
    })
}

fn parameter_sweep(inputs: usize) -> Value {
    Value::Array(
        [4usize, 6, 8, 10, 12, 14, 16]
            .into_iter()
            .map(|depth| {
                let repeats = 128usize.div_ceil(depth);
                let parts = voleith::proof_size(inputs, depth, repeats);
                let get = |name: &str| {
                    parts
                        .iter()
                        .find(|(key, _)| *key == name)
                        .map(|(_, value)| *value)
                        .unwrap_or(0)
                };
                json!({
                    "depth": depth,
                    "leaves_per_tree": 1usize << depth,
                    "repeats": repeats,
                    "soundness_bits": depth * repeats,
                    "bytes": get("total"),
                    "hashes": get("hashes"),
                })
            })
            .collect(),
    )
}

fn linear_code_arithmetic(inputs: usize, depth: usize) -> Value {
    let distance = 128usize.div_ceil(depth);
    let mut code_only: Option<Value> = None;
    let mut complete: Option<Value> = None;
    for k_c in [4usize, 8, 16, 32, 64, 128] {
        let n_c = k_c + distance - 1;
        let rows = inputs.div_ceil(k_c);
        let trees = n_c * depth * SEED_BYTES + n_c * COMMIT_BYTES + COMMIT_BYTES;
        let naive = trees + inputs * 16 + rows * (n_c - k_c) * 16 + n_c * 16 + 16;
        let full = trees
            + inputs * 16
            + (2 * rows + 2) * (n_c - k_c) * 16
            + (rows + 1) * n_c * 16
            + 3 * 16;
        let hashes = n_c * (1usize << depth) * 2;
        let base = json!({"k_C": k_c, "n_C": n_c, "d_C": distance, "rows": rows, "hashes": hashes});
        if code_only
            .as_ref()
            .is_none_or(|best| naive < best["bytes"].as_u64().unwrap_or(u64::MAX) as usize)
        {
            let mut value = base.clone();
            value["bytes"] = json!(naive);
            code_only = Some(value);
        }
        if complete
            .as_ref()
            .is_none_or(|best| full < best["bytes"].as_u64().unwrap_or(u64::MAX) as usize)
        {
            let mut value = base;
            value["bytes"] = json!(full);
            complete = Some(value);
        }
    }
    let mut code = code_only.unwrap();
    code["caveat"] = json!("unreachable for a within-block inner product: soundness falls to |S_Delta|^-1 = 2^-8. Kept because it is the figure this file used to report and the correction is the finding");
    let mut full = complete.unwrap();
    full["protocol"] = json!("Pi_2D-LC, eprint 2023/996 figure 6");
    json!({
        "note": "arithmetic only; Pi_2D-LC is not implemented",
        "depth": depth,
        "n_values": inputs,
        "code_swap_only": code,
        "protocol_complete": full,
    })
}

fn print_arm(name: &str, inputs: usize, row: &Value) {
    println!(
        "{name:>9} {inputs:>4} inputs  prove {:>20}  verify {:>20}  {:>7} B  accepted={}",
        render(&row["prove_ms"], " ms"),
        render(&row["verify_ms"], " ms"),
        row["bytes"]["exact"],
        zkpi_harness::value_display(&row["accepted"]),
    );
}

fn render(summary: &Value, unit: &str) -> String {
    let n = summary["n"].as_u64().unwrap_or(0);
    if n == 0 {
        return "—".into();
    }
    let mean = summary["mean"].as_f64().unwrap_or(0.0);
    match summary["sd"].as_f64() {
        Some(sd) => format!("{mean:.2} ± {sd:.2}{unit} (n={n})"),
        None => format!("{mean:.2}{unit} (n=1)"),
    }
}

fn mask_bits(inputs: usize, value_bits: usize) -> usize {
    value_bits + 40 + bit_length(inputs.saturating_sub(1)) + 40
}

fn bit_length(value: usize) -> usize {
    if value == 0 {
        0
    } else {
        (usize::BITS - value.leading_zeros()) as usize
    }
}

fn scalar(value: u128) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&value.to_le_bytes());
    Scalar::from_bytes_mod_order(bytes)
}

fn random_bits(bits: usize, rng: &mut OsRng) -> u128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    let value = u128::from_le_bytes(bytes);
    if bits >= 128 {
        value
    } else {
        value & ((1u128 << bits) - 1)
    }
}

fn round_places(value: f64, places: i32) -> f64 {
    let scale = 10f64.powi(places);
    zkfmi_measure::rounding::round_half_even(value * scale) as f64 / scale
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options {
        inputs: vec![16, 64, 167],
        repeats: 30,
        depth: voleith::DEFAULT_DEPTH,
        tree_repeats: voleith::DEFAULT_REPEATS,
        phases: false,
        out: zkpi_harness::repo_root().join("artifacts/voleith.json"),
        arithmetic_only: false,
    };
    let raw = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < raw.len() {
        match raw[index].to_string_lossy().as_ref() {
            "--inputs" => {
                options.inputs = parse_many(&raw, &mut index, "--inputs")?;
                continue;
            }
            "--repeats" => {
                options.repeats = parse_value(value(&raw, &mut index, "--repeats")?, "--repeats")?
            }
            "--depth" => {
                options.depth = parse_value(value(&raw, &mut index, "--depth")?, "--depth")?
            }
            "--tree-repeats" => {
                options.tree_repeats =
                    parse_value(value(&raw, &mut index, "--tree-repeats")?, "--tree-repeats")?
            }
            "--phases" => options.phases = true,
            "--out" => options.out = PathBuf::from(value(&raw, &mut index, "--out")?),
            "--arithmetic-only" => options.arithmetic_only = true,
            unknown => return Err(format!("unknown argument {unknown}").into()),
        }
        index += 1;
    }
    Ok(options)
}

fn parse_many<T>(raw: &[OsString], index: &mut usize, name: &str) -> HarnessResult<Vec<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let mut values = Vec::new();
    *index += 1;
    while *index < raw.len() && !raw[*index].to_string_lossy().starts_with("--") {
        values.push(parse_value(raw[*index].clone(), name)?);
        *index += 1;
    }
    Ok(values)
}

fn value(raw: &[OsString], index: &mut usize, name: &str) -> HarnessResult<OsString> {
    *index += 1;
    raw.get(*index)
        .cloned()
        .ok_or_else(|| format!("{name} expects a value").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &[u8] = b"ctx";

    fn values() -> Vec<u128> {
        (0..10).map(|index| 37 * index + 5).collect()
    }

    #[test]
    fn both_schemes_satisfy_the_seam() {
        let vals = values();
        let mut rng = OsRng;

        let pedersen_meta = voleith::linear_proof_metadata("pedersen").unwrap();
        assert!(pedersen_meta.publicly_verifiable);
        let key = Pedersen::new(b"qomm:pedersen:v1");
        let pedersen = prove_pedersen(&key, &vals, CONTEXT, &mut rng);
        assert_eq!(
            verify_pedersen(&key, &pedersen, CONTEXT),
            (true, "ok".into())
        );
        assert_eq!(
            pedersen_size(vals.len())
                .values()
                .filter_map(Value::as_u64)
                .sum::<u64>(),
            (vals.len() * 32 + 3 * 32) as u64
        );

        let voleith_meta = voleith::linear_proof_metadata("voleith").unwrap();
        assert!(voleith_meta.publicly_verifiable);
        let proof = voleith::prove(&vals, CONTEXT, 4, 4, &mut rng).unwrap();
        assert_eq!(voleith::verify(&proof, CONTEXT), (true, "ok".into()));
        assert_eq!(
            proof.size_bytes(),
            proof
                .size_breakdown()
                .iter()
                .map(|(_, bytes)| bytes)
                .sum::<usize>()
        );
    }

    #[test]
    fn a_proof_does_not_verify_under_another_context() {
        let vals = values();
        let mut rng = OsRng;

        let key = Pedersen::new(b"qomm:pedersen:v1");
        let pedersen = prove_pedersen(&key, &vals, CONTEXT, &mut rng);
        assert_eq!(
            verify_pedersen(&key, &pedersen, CONTEXT),
            (true, "ok".into())
        );
        let (ok, why) = verify_pedersen(&key, &pedersen, b"elsewhere");
        assert!(!ok);
        assert!(why.contains("combination 0"), "wrong refusal check: {why}");

        let proof = voleith::prove(&vals, CONTEXT, 4, 4, &mut rng).unwrap();
        assert_eq!(voleith::verify(&proof, CONTEXT), (true, "ok".into()));
        let (ok, why) = voleith::verify(&proof, b"elsewhere");
        assert!(!ok);
        assert!(why.contains("does not hold"), "wrong refusal check: {why}");
    }

    #[test]
    fn the_code_swap_alone_still_reproduces_the_figure_it_used_to_report() {
        let arithmetic = linear_code_arithmetic(167, 8);
        let best = &arithmetic["code_swap_only"];
        assert_eq!(
            (
                best["k_C"].as_u64(),
                best["n_C"].as_u64(),
                best["d_C"].as_u64()
            ),
            (Some(16), Some(31), Some(16))
        );
        assert_eq!(best["bytes"], 10_816);
        assert_eq!(best["hashes"], 15_872);
    }

    #[test]
    fn the_protocol_that_makes_the_code_usable_costs_most_of_the_saving() {
        let arithmetic = linear_code_arithmetic(167, 8);
        let best = &arithmetic["protocol_complete"];
        assert_eq!(best["bytes"], 18_896);
        assert_eq!(best["k_C"], 32);
        assert_eq!(round_places(45_616.0 / 18_896.0, 1), 2.4);
        assert_eq!(round_places(18_896.0 / 5_440.0, 1), 3.5);
        assert!(best["bytes"].as_u64() > arithmetic["code_swap_only"]["bytes"].as_u64());
    }
}
