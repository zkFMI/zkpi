use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use zkpi_harness::{parse_value, timing_summary, write_pretty_json, HarnessResult};
use zkfmi_zk::bitrange::{prove_bounded, verify_bounded, BoundedProof};
use zkfmi_zk::oneofmany;
use zkfmi_zk::or_dleq::{self, Statement};
use zkfmi_zk::Pedersen;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

const GK_TRANSCRIPT: &[u8] = b"qomm:gk:compare";

struct Options {
    out: PathBuf,
    sizes: Vec<usize>,
    counts: Vec<usize>,
    repeats: usize,
}

struct RangeItem {
    commitment: RistrettoPoint,
    proof: BoundedProof,
    low: i64,
    high: i64,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> HarnessResult<()> {
    let options = parse_args()?;
    println!("== one-out-of-N: OR composition vs Groth-Kohlweiss ==");
    let one_of_many = one_of_many(&options.sizes, options.repeats)?;
    println!("== range proofs: cost per proof as the count grows ==");
    let ranges = ranges(&options.counts, options.repeats, 0, 1_023)?;

    let crossover_bytes = one_of_many.iter().find_map(|row| {
        (row["gk_bytes"]["exact"].as_u64()? < row["or_bytes"]["exact"].as_u64()?)
            .then(|| row["size"].as_u64())
            .flatten()
    });
    let crossover_prove = one_of_many.iter().find_map(|row| {
        separated(&row["gk_prove"], &row["or_prove"])
            .then(|| row["size"].as_u64())
            .flatten()
    });
    let payload = json!({
        "host": zkfmi_measure::hosts::this_host(),
        "one_of_many": one_of_many,
        "ranges": ranges,
        "gk_smaller_from_size": crossover_bytes,
        "gk_faster_to_prove_from_size": crossover_prove,
    });
    write_pretty_json(Some(&options.out), &payload)?;
    println!(
        "\n  GK proof becomes smaller from N={}",
        display_option(crossover_bytes)
    );
    println!(
        "  GK becomes faster to prove from N={}",
        display_option(crossover_prove)
    );
    println!("wrote {}", options.out.display());
    Ok(())
}

fn one_of_many(sizes: &[usize], repeats: usize) -> HarnessResult<Vec<Value>> {
    let key = Pedersen::new(b"qomm:gk:v1");
    let mut rows = Vec::with_capacity(sizes.len());
    for &size in sizes {
        let index = size / 2;
        let (commitments, randomness) = build_set(&key, size, index)?;
        let mut transcript = Transcript::new(GK_TRANSCRIPT);
        let gk_proof = oneofmany::prove(
            &key,
            &mut transcript,
            &commitments,
            index,
            &randomness,
            &mut OsRng,
        )?;
        let mut transcript = Transcript::new(GK_TRANSCRIPT);
        if !oneofmany::verify(&key, &mut transcript, &commitments, &gk_proof) {
            return Err(format!("N={size}: Groth-Kohlweiss fixture did not verify").into());
        }

        let (points, secrets) = build_registry(size, 7);
        let registry_id = b"fixture";
        let scope = b"qomm:quote:v1";
        let context_hash = Sha256::digest(b"context");
        let statement = Statement {
            registry_id,
            points: &points,
            scope,
            context_hash: &context_hash,
        };
        let or_proof = or_dleq::prove(&statement, &secrets[index], index, &mut OsRng)?;
        if !or_dleq::verify(&statement, &or_proof) {
            return Err(format!("N={size}: OR fixture did not verify").into());
        }

        let row = json!({
            "size": size,
            "or_prove": timed(|| {
                black_box(or_dleq::prove(&statement, &secrets[index], index, &mut OsRng).expect("valid fixture"));
            }, repeats),
            "or_verify": timed(|| {
                black_box(or_dleq::verify(&statement, &or_proof));
            }, repeats),
            "or_bytes": {"exact": or_proof.size_bytes()},
            "gk_prove": timed(|| {
                let mut transcript = Transcript::new(GK_TRANSCRIPT);
                black_box(oneofmany::prove(
                    &key,
                    &mut transcript,
                    &commitments,
                    index,
                    &randomness,
                    &mut OsRng,
                ).expect("valid fixture"));
            }, repeats),
            "gk_verify": timed(|| {
                let mut transcript = Transcript::new(GK_TRANSCRIPT);
                black_box(oneofmany::verify(&key, &mut transcript, &commitments, &gk_proof));
            }, repeats),
            "gk_bytes": {"exact": gk_proof.size_bytes()},
        });
        println!(
            "  N={size:4}  OR prove {:7.2} verify {:7.2} {:6} B   |   GK prove {:7.2} verify {:7.2} {:6} B",
            mean(&row["or_prove"]),
            mean(&row["or_verify"]),
            row["or_bytes"]["exact"].as_u64().unwrap_or_default(),
            mean(&row["gk_prove"]),
            mean(&row["gk_verify"]),
            row["gk_bytes"]["exact"].as_u64().unwrap_or_default(),
        );
        rows.push(row);
    }
    Ok(rows)
}

fn build_set(
    key: &Pedersen,
    size: usize,
    index: usize,
) -> HarnessResult<(Vec<RistrettoPoint>, Scalar)> {
    if !size.is_power_of_two() || size < 2 || index >= size {
        return Err("this implementation takes a power-of-two set of at least two".into());
    }
    let randomness = Scalar::random(&mut OsRng);
    let commitments = (0..size)
        .map(|position| {
            if position == index {
                key.commit(&Scalar::ZERO, &randomness)
            } else {
                key.commit(&Scalar::random(&mut OsRng), &Scalar::random(&mut OsRng))
            }
        })
        .collect();
    Ok((commitments, randomness))
}

fn build_registry(size: usize, seed: u64) -> (Vec<RistrettoPoint>, Vec<Scalar>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let secrets: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut rng)).collect();
    let points = secrets
        .iter()
        .map(|secret| RISTRETTO_BASEPOINT_POINT * secret)
        .collect();
    (points, secrets)
}

fn ranges(counts: &[usize], repeats: usize, low: i64, high: i64) -> HarnessResult<Vec<Value>> {
    let key = Pedersen::new(b"qomm:rule:v1");
    let mut rows = Vec::with_capacity(counts.len());
    for &count in counts {
        let mut items = Vec::with_capacity(count);
        for index in 0..count {
            let context = format!("cmp:{index}");
            let (commitment, proof, _) = prove_bounded(
                &key,
                500 + index as i64,
                &Scalar::random(&mut OsRng),
                low,
                high,
                context.as_bytes(),
                &mut OsRng,
            )?;
            items.push(RangeItem {
                commitment,
                proof,
                low,
                high,
            });
        }
        let verify_all = timed(
            || {
                black_box(items.iter().enumerate().all(|(index, item)| {
                    verify_bounded(
                        &key,
                        &item.commitment,
                        &item.proof,
                        item.low,
                        item.high,
                        format!("cmp:{index}").as_bytes(),
                    )
                }));
            },
            repeats,
        );
        let prove_one = timed(
            || {
                black_box(
                    prove_bounded(
                        &key,
                        500,
                        &Scalar::random(&mut OsRng),
                        low,
                        high,
                        b"cmp:0",
                        &mut OsRng,
                    )
                    .expect("valid range fixture"),
                );
            },
            repeats,
        );
        let row = json!({
            "count": count,
            "prove_one": prove_one,
            "verify_all": verify_all,
            "verify_per_proof_ms": mean(&verify_all) / count as f64,
            "bytes_per_proof": {"exact": 32 * (2 * span_bits(low, high)? + 3)},
        });
        println!(
            "  {count:3} ranges  verify {:7.2} ms ({:6.2} ms each)",
            mean(&row["verify_all"]),
            row["verify_per_proof_ms"].as_f64().unwrap_or_default(),
        );
        rows.push(row);
    }
    Ok(rows)
}

fn span_bits(low: i64, high: i64) -> HarnessResult<usize> {
    let span = high.checked_sub(low).ok_or("empty interval")?;
    if span < 0 {
        return Err("empty interval".into());
    }
    Ok((64 - (span as u64).leading_zeros()).max(1) as usize)
}

fn timed(mut operation: impl FnMut(), repeats: usize) -> Value {
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let started = Instant::now();
        operation();
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    timing_summary(&samples)
}

fn mean(summary: &Value) -> f64 {
    summary["mean"].as_f64().unwrap_or_default()
}

fn separated(left: &Value, right: &Value) -> bool {
    match (left["sd"].as_f64(), right["sd"].as_f64()) {
        (Some(left_sd), Some(right_sd)) => mean(left) + left_sd < mean(right) - right_sd,
        _ => mean(left) < mean(right),
    }
}

fn display_option(value: Option<u64>) -> String {
    value.map_or_else(|| "None".into(), |value| value.to_string())
}

fn parse_args() -> HarnessResult<Options> {
    let mut out = None;
    let mut sizes = vec![4, 8, 16, 32, 64, 128];
    let mut counts = vec![1, 4, 16, 64];
    let mut repeats = 5;
    let mut args = std::env::args_os().skip(1).peekable();
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--out") => out = Some(PathBuf::from(next(&mut args, "--out")?)),
            Some("--sizes") => sizes = parse_many(&mut args, "--sizes")?,
            Some("--counts") => counts = parse_many(&mut args, "--counts")?,
            Some("--repeats") => repeats = parse_value(next(&mut args, "--repeats")?, "--repeats")?,
            Some("-h" | "--help") => {
                println!(
                    "usage: zk_compare --out PATH [--sizes N ...] [--counts N ...] [--repeats N]"
                );
                std::process::exit(0);
            }
            Some(value) => return Err(format!("unrecognised argument {value}").into()),
            None => return Err("argument is not valid UTF-8".into()),
        }
    }
    if sizes.is_empty()
        || counts.is_empty()
        || counts.contains(&0)
        || repeats == 0
        || sizes
            .iter()
            .any(|size| !size.is_power_of_two() || *size < 2)
    {
        return Err("sizes must be powers of two >= 2; counts and repeats must be positive".into());
    }
    Ok(Options {
        out: out.ok_or("--out is required")?,
        sizes,
        counts,
        repeats,
    })
}

fn next(
    args: &mut std::iter::Peekable<impl Iterator<Item = OsString>>,
    name: &str,
) -> HarnessResult<OsString> {
    args.next()
        .ok_or_else(|| format!("argument {name} expects one value").into())
}

fn parse_many(
    args: &mut std::iter::Peekable<impl Iterator<Item = OsString>>,
    name: &str,
) -> HarnessResult<Vec<usize>> {
    let mut values = Vec::new();
    while args
        .peek()
        .and_then(|value| value.to_str())
        .is_some_and(|value| !value.starts_with("--"))
    {
        values.push(parse_value(next(args, name)?, name)?);
    }
    if values.is_empty() {
        return Err(format!("argument {name} expects at least one value").into());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_sizes_match_the_locked_construction() {
        let rows = one_of_many(&[4, 8, 16], 1).unwrap();
        assert_eq!(rows[0]["or_bytes"]["exact"], 288);
        assert_eq!(rows[0]["gk_bytes"]["exact"], 480);
        assert_eq!(rows[2]["or_bytes"]["exact"], 1_056);
        assert_eq!(rows[2]["gk_bytes"]["exact"], 928);
    }

    #[test]
    fn bounded_range_fixture_verifies() {
        let rows = ranges(&[1, 4], 1, 0, 1_023).unwrap();
        assert_eq!(rows[0]["bytes_per_proof"]["exact"], 736);
        assert_eq!(rows[1]["count"], 4);
    }
}
