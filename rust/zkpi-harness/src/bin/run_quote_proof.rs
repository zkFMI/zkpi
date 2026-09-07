use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use zkpi_harness::{parse_value, timing_summary, write_pretty_json, HarnessResult};
use zkfmi_measure::deterministic_random::DeterministicRng;
use qomm_proofs::quote_proof::{MakerWitness, QuoteCircuit, Registered};
use qomm_proofs::threshold_sigma::{deal, joint_opening_from_shares, joint_prove_opening};
use zkfmi_zk::bitrange::prove_bounded;
use zkfmi_zk::pedersen::Pedersen;
use zkfmi_zk::sigma::verify_opening;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Instant;

const SENTINEL: i64 = 1 << 20;
const CONTEXT: &[u8] = b"";

struct Options {
    out: PathBuf,
    sizes: Vec<usize>,
    repeats: usize,
    nodes: usize,
    threshold: usize,
}

fn main() {
    if let Err(error) = run_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run_main() -> HarnessResult<()> {
    let options = parse_args()?;
    if options.sizes.is_empty() || options.sizes.contains(&0) {
        return Err("--sizes must contain positive maker counts".into());
    }
    if options.repeats == 0 {
        return Err("--repeats must be positive".into());
    }
    if options.nodes <= options.threshold {
        return Err("--nodes must be greater than --threshold".into());
    }
    let mut rng = OsRng;
    println!("== proof of a correct quote ==");
    let scaling = scaling(&options, &mut rng)?;
    println!("== forgery controls ==");
    let controls = forgery_controls(&mut rng)?;
    println!("== joint assembly by the computing nodes ==");
    let quorums = [
        (1..=options.threshold + 1).collect::<Vec<_>>(),
        (1..=options.nodes).collect::<Vec<_>>(),
    ];
    let joint = joint_path(options.nodes, options.threshold, &quorums, &mut rng)?;
    println!("== calibration ==");
    let calibration = calibration(options.repeats, &mut rng)?;
    let payload = json!({
        "host": zkfmi_measure::hosts::this_host(),
        "scaling": scaling,
        "forgery_controls": controls,
        "joint": joint,
        "nodes": options.nodes,
        "threshold": options.threshold,
        "calibration": calibration,
    });
    write_pretty_json(Some(&options.out), &payload)?;
    println!("wrote {}", options.out.display());
    Ok(())
}

fn span_bits(n_slots: usize) -> usize {
    let upper = (SENTINEL as u64) * n_slots as u64 * 2;
    (u64::BITS - upper.leading_zeros()) as usize
}

fn makers_for(n: usize, seed: u64, rng: &mut OsRng) -> Vec<MakerWitness> {
    let mut values = DeterministicRng::new(seed);
    (0..n)
        .map(|_| MakerWitness {
            ask_level: 100_000 + values.randint(-15, 15),
            spread: values.randint(10, 80),
            slope: *values.choice(&[0, 1, 2]),
            invcoef: *values.choice(&[0, 1, 2]),
            inv: values.randint(0, 50),
            maxqty: *values.choice(&[200, 400]),
            expiry: 1_000 + values.randint(1, 600),
            active: true,
            blindings: Registered::fresh(rng),
        })
        .collect()
}

fn cleartext_winner(makers: &[MakerWitness], qty: i64) -> usize {
    makers
        .iter()
        .enumerate()
        .min_by_key(|(_, maker)| maker.ask_level + maker.slope * qty + maker.invcoef * maker.inv)
        .map(|(index, _)| index)
        .expect("the caller supplies at least one maker")
}

fn prove_quote(
    circuit: &QuoteCircuit,
    makers: &[MakerWitness],
    qty: i64,
    rng: &mut OsRng,
) -> HarnessResult<(
    qomm_proofs::quote_proof::QuoteProof,
    qomm_proofs::quote_proof::Public,
)> {
    circuit
        .prove(
            makers,
            qty,
            0,
            1_000,
            SENTINEL,
            makers.len() as i64,
            CONTEXT,
            rng,
            [0u8; 32],
            0,
        )
        .map_err(Into::into)
}

fn scaling(options: &Options, rng: &mut OsRng) -> HarnessResult<Vec<Value>> {
    let mut rows = Vec::new();
    for &n in &options.sizes {
        let bits = span_bits(n);
        let circuit = QuoteCircuit::new(24, bits);
        let makers = makers_for(n, 5, rng);
        let (proof, public) = prove_quote(&circuit, &makers, 100, rng)?;
        let verified = circuit.verify(&proof, &public, CONTEXT).is_ok();
        let mut prove_times = Vec::new();
        let mut verify_times = Vec::new();
        for _ in 0..options.repeats {
            let started = Instant::now();
            let _ = prove_quote(&circuit, &makers, 100, rng)?;
            prove_times.push(started.elapsed().as_secs_f64() * 1e3);
            let started = Instant::now();
            let _ = circuit.verify(&proof, &public, CONTEXT);
            verify_times.push(started.elapsed().as_secs_f64() * 1e3);
        }
        let matches = proof.winner_index == cleartext_winner(&makers, 100);
        rows.push(json!({
            "makers": n,
            "verified": verified,
            "message": if verified { "ok" } else { "verification failed" },
            "winner": proof.winner_index,
            "matches_cleartext": matches,
            "prove": timing_summary(&prove_times),
            "verify": timing_summary(&verify_times),
            "range_bits": {"exact": bits},
        }));
        println!("  M={n:3}  verified={verified}  winner_correct={matches}");
    }
    Ok(rows)
}

fn forgery_controls(rng: &mut OsRng) -> HarnessResult<Vec<Value>> {
    let circuit = QuoteCircuit::new(24, span_bits(8));
    let makers = makers_for(8, 5, rng);
    let (mut proof, public) = prove_quote(&circuit, &makers, 100, rng)?;
    let mut out = Vec::new();

    let winner = proof.winner_index;
    let other = (0..8).find(|index| *index != winner).unwrap();
    proof.winner_index = other;
    let rejected = circuit.verify(&proof, &public, CONTEXT).is_err();
    proof.winner_index = winner;
    out.push(control(
        "winner swapped to a non-minimal maker",
        rejected,
        "the published winner value is not what the commitment opens to",
    ));

    let mut stale = makers.clone();
    stale[0].expiry = 999;
    let (stale_proof, stale_public) = prove_quote(&circuit, &stale, 100, rng)?;
    let stale_ok = circuit.verify(&stale_proof, &stale_public, CONTEXT).is_ok();
    out.push(control(
        "expired maker appears and cannot win",
        stale_ok && stale_proof.winner_index != 0,
        &format!("gated off; winner is maker {}", stale_proof.winner_index),
    ));

    let (wide_proof, wide_public) = prove_quote(&circuit, &makers, 100_000, rng)?;
    let wide_ok = circuit.verify(&wide_proof, &wide_public, CONTEXT).is_ok();
    out.push(control(
        "request nobody can fill answers `no quote`",
        wide_ok && wide_proof.winner_value >= SENTINEL as u64,
        "every maker gated to the sentinel",
    ));

    let original_ok = proof.maker_proofs[winner].commitments.ok;
    proof.maker_proofs[winner].commitments.ok = circuit
        .key
        .commit(&Scalar::ZERO, &Scalar::random(&mut *rng));
    let gated_rejected = circuit.verify(&proof, &public, CONTEXT).is_err();
    proof.maker_proofs[winner].commitments.ok = original_ok;
    out.push(control(
        "the winning maker switched off",
        gated_rejected,
        &format!("maker {winner}: eligibility is not the conjunction of its three tests"),
    ));

    proof.key_commitments.swap(0, 1);
    let minimality_rejected = circuit.verify(&proof, &public, CONTEXT).is_err();
    proof.key_commitments.swap(0, 1);
    out.push(control(
        "minimality proofs swapped between makers",
        minimality_rejected,
        "maker 0: not shown to be at least the winner",
    ));

    let negative_rejected = prove_bounded(
        &Pedersen::new(b"qomm:false-winner"),
        -1,
        &Scalar::random(&mut *rng),
        0,
        (1i64 << span_bits(8)) - 1,
        b"x",
        rng,
    )
    .is_err();
    out.push(control(
        "minimality for a false winner",
        negative_rejected,
        &format!("value -1 outside [0, 2^{})", span_bits(8)),
    ));

    for row in &out {
        println!("  {:44} rejected={}", row["control"], row["rejected"]);
    }
    Ok(out)
}

fn control(name: &str, rejected: bool, reason: &str) -> Value {
    json!({"control": name, "rejected": rejected, "reason": reason})
}

fn joint_path(
    nodes: usize,
    threshold: usize,
    quorums: &[Vec<usize>],
    rng: &mut OsRng,
) -> HarnessResult<Vec<Value>> {
    let key = Pedersen::new(b"qomm:quote:v1");
    let parties = (1..=nodes).collect::<Vec<_>>();
    let value = Scalar::from(123_456u64);
    let blinding = Scalar::random(&mut *rng);
    let shares = deal(&key, &value, &blinding, &parties, threshold, rng)?;
    let mut rows = Vec::new();
    for quorum in quorums {
        let mut prove_transcript = Transcript::new(b"qomm:quote:joint");
        let (proof, _) =
            joint_prove_opening(&key, &shares, quorum, &mut prove_transcript, None, rng)?;
        let mut verify_transcript = Transcript::new(b"qomm:quote:joint");
        let verified = verify_opening(&key, &mut verify_transcript, &shares.commitment, &proof);
        let mut audited = Vec::new();
        let mut unaudited = Vec::new();
        for _ in 0..20 {
            let started = Instant::now();
            let mut transcript = Transcript::new(b"qomm:quote:joint");
            let _ = joint_prove_opening(&key, &shares, quorum, &mut transcript, None, rng)?;
            audited.push(started.elapsed().as_secs_f64() * 1e3);

            let started = Instant::now();
            let mut transcript = Transcript::new(b"qomm:quote:joint");
            let _ = joint_opening_from_shares(
                &key,
                &shares.commitment,
                &shares.value_shares,
                &shares.blinding_shares,
                threshold,
                quorum,
                &mut transcript,
                rng,
            )?;
            unaudited.push(started.elapsed().as_secs_f64() * 1e3);
        }
        let audited_summary = timing_summary(&audited);
        let unaudited_summary = timing_summary(&unaudited);
        let factor = audited_summary["mean"].as_f64().unwrap()
            / unaudited_summary["mean"].as_f64().unwrap().max(1e-9);
        let no_node_holds = shares.value_shares.values().all(|share| *share != value);
        rows.push(json!({
            "quorum": quorum,
            "size": quorum.len(),
            "verified_by_ordinary_verifier": verified,
            "assemble": audited_summary,
            "assemble_without_attribution": unaudited_summary,
            "attribution_factor": factor,
            "no_node_holds_witness": no_node_holds,
        }));
        println!("  quorum of {}: verified={verified}", quorum.len());
    }
    Ok(rows)
}

fn calibration(repeats: usize, rng: &mut OsRng) -> HarnessResult<Value> {
    let key = Pedersen::new(b"qomm:defmi:calib");
    let point = RistrettoPoint::mul_base(&Scalar::from(7u64));
    let mut scalar_samples = Vec::new();
    for _ in 0..repeats.max(50) {
        let started = Instant::now();
        std::hint::black_box(point * Scalar::from(12_345u64));
        scalar_samples.push(started.elapsed().as_secs_f64() * 1e6);
    }
    let mut range_samples = Vec::new();
    for _ in 0..repeats {
        let blinding = Scalar::random(&mut *rng);
        let started = Instant::now();
        let _ = prove_bounded(&key, 1_234, &blinding, 0, (1i64 << 40) - 1, b"calib", rng)?;
        range_samples.push(started.elapsed().as_secs_f64() * 1e3);
    }
    Ok(json!({
        "scalar_mult_us": timing_summary(&scalar_samples),
        "range_proof_40bit_ms": timing_summary(&range_samples),
    }))
}

fn parse_args() -> HarnessResult<Options> {
    let mut out = None;
    let mut sizes = vec![4, 8, 16, 32];
    let mut repeats = 15;
    let mut nodes = 7;
    let mut threshold = 2;
    let raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut index = 0;
    while index < raw.len() {
        match raw[index].to_str() {
            Some("--out") => {
                index += 1;
                out = Some(PathBuf::from(raw.get(index).ok_or("--out expects a path")?));
            }
            Some("--sizes") => {
                sizes.clear();
                index += 1;
                while index < raw.len() && !raw[index].to_string_lossy().starts_with("--") {
                    sizes.push(parse_value(raw[index].clone(), "--sizes")?);
                    index += 1;
                }
                continue;
            }
            Some("--repeats") => {
                index += 1;
                repeats = parse_value(
                    raw.get(index).ok_or("--repeats expects a value")?.clone(),
                    "--repeats",
                )?;
            }
            Some("--nodes") => {
                index += 1;
                nodes = parse_value(
                    raw.get(index).ok_or("--nodes expects a value")?.clone(),
                    "--nodes",
                )?;
            }
            Some("--threshold") => {
                index += 1;
                threshold = parse_value(
                    raw.get(index).ok_or("--threshold expects a value")?.clone(),
                    "--threshold",
                )?;
            }
            Some(other) => return Err(format!("unknown argument {other}").into()),
            None => return Err("arguments must be UTF-8".into()),
        }
        index += 1;
    }
    Ok(Options {
        out: out.ok_or("--out is required")?,
        sizes,
        repeats,
        nodes,
        threshold,
    })
}
