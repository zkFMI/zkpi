//! Operator custody management. Secret material is never printed.

use qomm_transport::key_management::{EncryptedKeyStore, KeyKind};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use zeroize::Zeroizing;

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        return Err("usage: qomm_key_tool <store> <passphrase-file> <init|public|generate|rotate|revoke> [purpose/key-id] [now] [lifetime/reason]".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&args[1])
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    // SAFETY: geteuid has no preconditions and returns no secret material.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 4096
    {
        return Err(
            "passphrase file must be an owner-only regular file of at most 4096 bytes".into(),
        );
    }
    let mut passphrase = Zeroizing::new(Vec::new());
    file.take(4097)
        .read_to_end(&mut passphrase)
        .map_err(|e| e.to_string())?;
    if passphrase.is_empty() || passphrase.len() > 4096 {
        return Err("invalid passphrase file length".into());
    }
    let store = EncryptedKeyStore::new(&args[0], &passphrase)?;
    match args[2].as_str() {
        "init" if args.len() == 3 => store.initialize()?,
        "public" if args.len() == 3 => {
            let snapshot = store.snapshot()?;
            println!(
                "{}",
                serde_json::json!({"version": snapshot.version, "generation": snapshot.generation, "keys": snapshot.keys})
            );
        }
        "generate" | "rotate" if args.len() == 6 => {
            let now = args[4].parse::<u64>().map_err(|e| e.to_string())?;
            let lifetime = args[5].parse::<u64>().map_err(|e| e.to_string())?;
            let key_id = if args[2] == "generate" {
                store.generate(
                    &args[3],
                    KeyKind::HybridSignature,
                    now,
                    lifetime,
                    BTreeMap::new(),
                )?
            } else {
                store.rotate(
                    &args[3],
                    KeyKind::HybridSignature,
                    now,
                    lifetime,
                    BTreeMap::new(),
                )?
            };
            println!(
                "{}",
                serde_json::json!({"key_id": key_id, "kind": "ed25519_mldsa65"})
            );
        }
        "revoke" if args.len() == 6 => store.revoke(
            &args[3],
            args[4].parse::<u64>().map_err(|e| e.to_string())?,
            &args[5],
        )?,
        _ => return Err("invalid custody command or argument count".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
