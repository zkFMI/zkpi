use qomm_batch_audit::{
    BatchContext, BatchProof, BatchStatement, PublicTransition, StateRoots, prove, statement,
    verify,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

const MAX_JSON_BYTES: u64 = 24 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizedPublicRecords {
    context: BatchContext,
    initial: StateRoots,
    transitions: Vec<PublicTransition>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditArtifact {
    statement: BatchStatement,
    proof: BatchProof,
}

fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_JSON_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err("input exceeds public-audit JSON limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err(
            "usage: qomm-batch-audit prove|verify finalized-records.json audit-artifact.json"
                .into(),
        );
    }
    let records: FinalizedPublicRecords = read_json(Path::new(&args[2]))?;
    let expected = statement(records.context, records.initial, &records.transitions)?;
    match args[1].to_str() {
        Some("prove") => {
            let proof = prove(&expected, &records.transitions)?;
            let bytes = serde_json::to_vec(&AuditArtifact {
                statement: expected,
                proof,
            })
            .map_err(|e| e.to_string())?;
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .open(&args[3])
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes).map_err(|e| e.to_string())?;
            file.write_all(b"\n").map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            println!("Complete public state-continuity STARK generated and verified.");
        }
        Some("verify") => {
            let artifact: AuditArtifact = read_json(Path::new(&args[3]))?;
            if artifact.statement != expected {
                return Err(
                    "artifact does not match the independent finalized-record source".into(),
                );
            }
            verify(&expected, &artifact.proof)?;
            println!("Complete public state-continuity STARK verified against expected records.");
        }
        _ => return Err("unknown public-audit operation".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("public audit: {error}");
        std::process::exit(1);
    }
}
