use curve25519_dalek::ristretto::{RistrettoPoint, RistrettoPoint as Point};
use curve25519_dalek::scalar::Scalar;
use zkpi_harness::{parse_value, rustc_version, timing_summary, write_pretty_json, HarnessResult};
use qomm_proofs::state_audit::{ChainError, InventoryLimit, StateAuditor, StateStep};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::Sha512;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

struct Options {
    out: PathBuf,
    lengths: Vec<usize>,
    limit: u64,
    ceiling: u64,
}

struct Chain {
    opening: Point,
    steps: Vec<StateStep>,
    limit: InventoryLimit,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> HarnessResult<()> {
    let options = parse_args()?;
    if options.limit > options.ceiling {
        return Err("--limit must not exceed --ceiling".into());
    }
    if options.lengths.contains(&0) {
        return Err("--lengths values must be positive".into());
    }
    let auditor = StateAuditor::new();
    let calibration = calibration(200);
    println!(
        "calibration: scalar mult {:.1} us",
        calibration["scalar_mult_us"]["mean"]
            .as_f64()
            .unwrap_or(0.0)
    );
    let mut chains = Vec::new();
    for &length in &options.lengths {
        let (row, _) = one_chain(&auditor, length, options.limit, options.ceiling)?;
        println!(
            "  {length:3} steps  prove {} ms/step  verify {:7.1} ms/step  {:} B/step  accepted={}",
            render(&row["prove_per_step"], 1),
            row["verify_ms_per_step"].as_f64().unwrap_or(0.0),
            row["step_bytes"]["exact"].as_u64().unwrap_or(0),
            zkpi_harness::value_display(&row["accepted"]),
        );
        chains.push(row);
    }
    let rejections = rejections(&auditor, options.limit, options.ceiling)?;
    for row in &rejections {
        println!(
            "  {:34} accepted={}",
            row["attack"].as_str().unwrap_or_default(),
            zkpi_harness::value_display(&row["accepted"]),
        );
    }
    if rejections
        .iter()
        .any(|row| row["accepted"].as_bool().unwrap_or(false))
    {
        eprintln!("A REJECTION ARM ACCEPTED. The audit is not checking.");
    }
    let payload = json!({
        "host": zkfmi_measure::hosts::this_host(),
        "rustc": rustc_version(),
        "group": "ed25519",
        "ceiling": options.ceiling,
        "limit": options.limit,
        "calibration": calibration,
        "chains": chains,
        "rejections": rejections,
    });
    write_pretty_json(Some(&options.out), &payload)?;
    println!("wrote {}", options.out.display());
    Ok(())
}

fn calibration(repeats: usize) -> Value {
    let point = RistrettoPoint::hash_from_bytes::<Sha512>(b"calibration");
    let scalar = Scalar::from(12_345u64);
    let mut samples = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let started = Instant::now();
        std::hint::black_box(point * scalar);
        samples.push(started.elapsed().as_secs_f64() * 1e6);
    }
    json!({"scalar_mult_us": timing_summary(&samples)})
}

fn one_chain(
    auditor: &StateAuditor,
    length: usize,
    limit_value: u64,
    ceiling_value: u64,
) -> HarnessResult<(Value, Chain)> {
    let limit_blinding = Scalar::random(&mut OsRng);
    let started = Instant::now();
    let limit = auditor.commit_limit(limit_value, &limit_blinding)?;
    let limit_ms = started.elapsed().as_secs_f64() * 1e3;

    let mut blinding = Scalar::random(&mut OsRng);
    let opening = auditor.key.commit(&Scalar::ZERO, &blinding);
    let mut inventory = 0i64;
    let mut steps = Vec::with_capacity(length);
    let mut prove_ms = Vec::with_capacity(length);
    let swing = (limit_value / 8).max(1) as i64;
    for index in 0..length {
        let filled = if index % 2 == 0 { -swing } else { swing };
        let new_blinding = Scalar::random(&mut OsRng);
        let started = Instant::now();
        let (step, next) = auditor.prove_update(
            index as u64,
            inventory,
            &blinding,
            filled,
            &Scalar::random(&mut OsRng),
            limit_value,
            &limit_blinding,
            &new_blinding,
            &mut OsRng,
        )?;
        prove_ms.push(started.elapsed().as_secs_f64() * 1e3);
        steps.push(step);
        inventory = next;
        blinding = new_blinding;
    }
    let started = Instant::now();
    let verified = auditor.verify_chain(&opening, &steps, &limit);
    let verify_ms = started.elapsed().as_secs_f64() * 1e3;
    let (accepted, reason) = verdict(verified);
    let row = json!({
        "steps": length,
        "limit_commit_ms": limit_ms,
        "prove_per_step": timing_summary(&prove_ms),
        "verify_total_ms": verify_ms,
        "verify_ms_per_step": verify_ms / length as f64,
        "accepted": accepted,
        "reason": reason,
        // boundary while the proof operations themselves use qomm-proofs.
        "step_bytes": {"exact": canonical_step_bytes(ceiling_value)},
    });
    Ok((
        row,
        Chain {
            opening,
            steps,
            limit,
        },
    ))
}

fn rejections(auditor: &StateAuditor, limit_value: u64, ceiling: u64) -> HarnessResult<Vec<Value>> {
    let mut rows = Vec::new();

    let (_, mut skipped) = one_chain(auditor, 3, limit_value, ceiling)?;
    skipped.steps.remove(1);
    let started = Instant::now();
    let verdict_value = auditor.verify_chain(&skipped.opening, &skipped.steps, &skipped.limit);
    rows.push(rejection(
        "replayed or skipped state",
        verdict_value,
        started,
    ));

    let (_, mut first) = one_chain(auditor, 3, limit_value, ceiling)?;
    let (_, mut other) = one_chain(auditor, 3, limit_value, ceiling)?;
    first.steps[1] = other.steps.remove(1);
    let started = Instant::now();
    let verdict_value = auditor.verify_chain(&first.opening, &first.steps, &first.limit);
    rows.push(rejection("forked state", verdict_value, started));

    let (_, honest) = one_chain(auditor, 3, limit_value, ceiling)?;
    let looser_value = limit_value.saturating_mul(2).min(ceiling);
    let looser = auditor.commit_limit(looser_value, &Scalar::random(&mut OsRng))?;
    let started = Instant::now();
    let verdict_value = auditor.verify_chain(&honest.opening, &honest.steps, &looser);
    rows.push(rejection(
        "limit swapped for a looser one",
        verdict_value,
        started,
    ));

    let blinding = Scalar::random(&mut OsRng);
    let breach = auditor.prove_update(
        0,
        limit_value as i64 - 1,
        &blinding,
        -(limit_value as i64),
        &Scalar::random(&mut OsRng),
        limit_value,
        &Scalar::random(&mut OsRng),
        &Scalar::random(&mut OsRng),
        &mut OsRng,
    );
    let new_inventory = limit_value.saturating_mul(2).saturating_sub(1);
    rows.push(match breach {
        Ok(_) => json!({
            "attack": "breach the committed limit",
            "accepted": true,
            "reason": "the prover built a step it should not have",
            "ms": 0.0,
        }),
        Err(_) => json!({
            "attack": "breach the committed limit",
            "accepted": false,
            "reason": format!("inventory {new_inventory} breaks the committed limit {limit_value}; the maker cannot prove this step and must decline the fill"),
            "ms": 0.0,
        }),
    });
    Ok(rows)
}

fn rejection(attack: &str, result: Result<(), ChainError>, started: Instant) -> Value {
    let (accepted, reason) = verdict(result);
    json!({"attack": attack, "accepted": accepted, "reason": reason, "ms": started.elapsed().as_secs_f64() * 1e3})
}

fn verdict(result: Result<(), ChainError>) -> (bool, String) {
    match result {
        Ok(()) => (true, "ok".into()),
        Err(ChainError::Forked { index, step }) => (
            false,
            format!("step {step} (index {index}) does not follow the state before it: a replayed or forked inventory"),
        ),
        Err(ChainError::Arithmetic { index, step } | ChainError::Containment { index, step }) => {
            (false, format!("step {step} (index {index}) failed its proofs"))
        }
        Err(ChainError::LimitNotInRange) => (false, "limit proof failed".into()),
        Err(ChainError::NotTheDealtState { index, step }) => {
            (false, format!("step {step} (index {index}) is not the dealt state"))
        }
    }
}

fn canonical_step_bytes(ceiling: u64) -> usize {
    let bits = (2 * ceiling).ilog2() as usize + 1;
    64 + 64 + 2 * bits * (32 * 2 + 32 * 3) + 32
}

fn render(summary: &Value, places: usize) -> String {
    let n = summary["n"].as_u64().unwrap_or(0);
    if n == 0 {
        return "—".into();
    }
    let mean = summary["mean"].as_f64().unwrap_or(0.0);
    match summary["sd"].as_f64() {
        Some(sd) => format!("{mean:.places$} ± {sd:.places$} (n={n})"),
        None => format!("{mean:.places$} (n=1)"),
    }
}

fn parse_args() -> HarnessResult<Options> {
    let mut options = Options {
        out: PathBuf::from("artifacts/state_audit.json"),
        lengths: vec![1, 5, 20, 50],
        limit: 4_000,
        ceiling: 1 << 13,
    };
    let raw = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < raw.len() {
        match raw[index].to_string_lossy().as_ref() {
            "--out" => options.out = PathBuf::from(value(&raw, &mut index, "--out")?),
            "--limit" => {
                options.limit = parse_value(value(&raw, &mut index, "--limit")?, "--limit")?
            }
            "--ceiling" => {
                options.ceiling = parse_value(value(&raw, &mut index, "--ceiling")?, "--ceiling")?
            }
            "--lengths" => {
                options.lengths = parse_many(&raw, &mut index, "--lengths")?;
                continue;
            }
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
