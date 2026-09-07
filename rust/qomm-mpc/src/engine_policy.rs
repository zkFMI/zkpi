//! Bind the native engine to the mandatory hybrid TLS adapter and build receipt.
//! A receipt is a local build trust boundary, not a remote attestation.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub const HEADER_SHA256: &str = "ccc7d6a496423ead58a3fc44f66a17f7fc692928395821bc546add38cefe58aa";
pub const RECEIPT: &str = ".pqc-tls.sha256";
pub const ARTIFACTS: [&str; 3] = [
    "Networking/ssl_sockets.h",
    "libSPDZ.so",
    "malicious-shamir-party.x",
];

pub fn verify(root: &Path) -> Result<(), String> {
    let receipt = std::fs::read_to_string(root.join(RECEIPT)).map_err(|_| {
        "MP-SPDZ requires the pinned hybrid TLS build receipt; classical engines are refused"
            .to_string()
    })?;
    let records = receipt
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    if records.len() != ARTIFACTS.len() {
        return Err("invalid hybrid engine receipt".into());
    }
    for (name, record) in ARTIFACTS.into_iter().zip(records) {
        if record.len() != 2
            || record[1] != name
            || record[0].len() != 64
            || (name == ARTIFACTS[0] && record[0] != HEADER_SHA256)
        {
            return Err(
                "hybrid engine receipt does not bind the pinned adapter and artifacts".into(),
            );
        }
        let mut file = std::fs::File::open(root.join(name))
            .map_err(|_| format!("missing hybrid engine artifact: {name}"))?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 65536];
        loop {
            let bytes = file
                .read(&mut buffer)
                .map_err(|_| format!("cannot read hybrid engine artifact: {name}"))?;
            if bytes == 0 {
                break;
            }
            hash.update(&buffer[..bytes]);
        }
        if format!("{:x}", hash.finalize()) != record[0] {
            return Err(format!("hybrid engine artifact changed: {name}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_classical_or_missing_engine_receipts() {
        let directory = tempfile::tempdir().unwrap();
        assert!(verify(directory.path())
            .unwrap_err()
            .contains("classical engines are refused"));
        let stale = ARTIFACTS
            .map(|name| format!("{}  {name}\n", "00".repeat(32)))
            .concat();
        std::fs::write(directory.path().join(RECEIPT), stale).unwrap();
        assert!(verify(directory.path())
            .unwrap_err()
            .contains("pinned adapter"));
    }

    #[test]
    fn refuses_an_adapter_whose_bytes_do_not_match_its_receipt() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("Networking")).unwrap();
        std::fs::write(directory.path().join(ARTIFACTS[0]), b"classical adapter").unwrap();
        let records = format!(
            "{HEADER_SHA256}  {}\n{}  {}\n{}  {}\n",
            ARTIFACTS[0],
            "00".repeat(32),
            ARTIFACTS[1],
            "00".repeat(32),
            ARTIFACTS[2]
        );
        std::fs::write(directory.path().join(RECEIPT), records).unwrap();
        assert!(verify(directory.path())
            .unwrap_err()
            .contains("artifact changed"));
    }
}
