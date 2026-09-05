use qomm_batch_audit::{BatchContext, PublicTransition, StateRoots};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Files(PathBuf);
impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_proves_verifies_and_requires_independent_matching_records() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".artifacts")
        .join(format!(
            "cli-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
    fs::create_dir_all(&path).unwrap();
    let files = Files(path);
    let initial = StateRoots {
        securities: [10; 32],
        cash: [20; 32],
    };
    let after = StateRoots {
        securities: [11; 32],
        cash: [21; 32],
    };
    let data = json!({
        "context": BatchContext { network_id: [1;32], deployment_id: [2;32], period: 17, partition: 0 },
        "initial": initial.clone(),
        "transitions": [PublicTransition { before: initial, after, zkpi_digest: [3;32], receipt_digest: [4;32], settled: true }]
    });
    let records = files.0.join("expected.json");
    let proof = files.0.join("proof.json");
    fs::write(&records, serde_json::to_vec(&data).unwrap()).unwrap();
    let run = |operation: &str| {
        Command::new(env!("CARGO_BIN_EXE_qomm-batch-audit"))
            .arg(operation)
            .arg(&records)
            .arg(&proof)
            .output()
            .unwrap()
    };
    let generated = run("prove");
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    assert!(run("verify").status.success());
    let saved = fs::read(&proof).unwrap();
    assert!(
        !run("prove").status.success(),
        "must not overwrite an existing artifact"
    );
    assert_eq!(saved, fs::read(&proof).unwrap());
    let mut unrelated = data.clone();
    unrelated["context"]["period"] = json!(18);
    fs::write(&records, serde_json::to_vec(&unrelated).unwrap()).unwrap();
    assert!(
        !run("verify").status.success(),
        "a proof cannot choose the verifier's expected period"
    );
    fs::write(&records, serde_json::to_vec(&data).unwrap()).unwrap();
    fs::write(&proof, &saved[..saved.len() / 2]).unwrap();
    assert!(!run("verify").status.success());
}
