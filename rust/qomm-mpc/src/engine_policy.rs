//! Bind the native engine to the mandatory hybrid TLS adapter and build receipt.
//! A receipt is a local build trust boundary, not a remote attestation.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub const HEADER_SHA256: &str = "ccc7d6a496423ead58a3fc44f66a17f7fc692928395821bc546add38cefe58aa";
pub const RECEIPT: &str = ".pqc-tls.sha256";
pub const ARTIFACTS: [&str; 3] = [
    "Networking/ssl_sockets.h",
    "libSPDZ.so",
    "malicious-shamir-party.x",
];

pub fn verify(root: &Path) -> Result<(), String> {
    verify_with_header(root, HEADER_SHA256)
}

fn verify_with_header(root: &Path, header_sha256: &str) -> Result<(), String> {
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
            || (name == ARTIFACTS[0] && record[0] != header_sha256)
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

/// Identity of one engine file as the file system reports it: size,
/// modification time and, on Unix, device and inode. Equal identity is
/// treated as unchanged bytes; any difference falls back to hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileIdentity {
    fn read(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::metadata(path).map_err(|_| {
            format!(
                "missing hybrid engine artifact: {}",
                path.file_name().and_then(|name| name.to_str()).unwrap_or("?")
            )
        })?;
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        })
    }
}

/// A verified engine root whose artifact identities were recorded at the
/// time of the full hash check. [`EnginePin::recheck`] costs four `stat`
/// calls when nothing changed and repeats the full check otherwise, so a
/// long-lived runner pays the 45 MB hash once per process, not per round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnginePin {
    root: PathBuf,
    header_sha256: String,
    receipt: FileIdentity,
    artifacts: [FileIdentity; ARTIFACTS.len()],
}

impl EnginePin {
    /// Run the full receipt check and record what the verified files look
    /// like to the file system.
    pub fn verify(root: &Path) -> Result<Self, String> {
        Self::verify_with_header(root, HEADER_SHA256)
    }

    fn verify_with_header(root: &Path, header_sha256: &str) -> Result<Self, String> {
        verify_with_header(root, header_sha256)?;
        let receipt = FileIdentity::read(&root.join(RECEIPT))?;
        let mut artifacts = Vec::with_capacity(ARTIFACTS.len());
        for name in ARTIFACTS {
            artifacts.push(FileIdentity::read(&root.join(name))?);
        }
        let artifacts = artifacts
            .try_into()
            .map_err(|_| "hybrid engine artifact list changed length".to_string())?;
        Ok(Self {
            root: root.to_path_buf(),
            header_sha256: header_sha256.to_string(),
            receipt,
            artifacts,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Cheap per-round check. Identical identities mean the bytes verified
    /// at pin time are still the bytes on disk; any difference (a rebuilt
    /// engine, a replaced receipt, a touched file) re-runs the full hash
    /// check, so a changed artifact is still refused before it is spawned.
    pub fn recheck(&self) -> Result<(), String> {
        let mut unchanged = FileIdentity::read(&self.root.join(RECEIPT))? == self.receipt;
        for (name, recorded) in ARTIFACTS.iter().zip(&self.artifacts) {
            unchanged &= FileIdentity::read(&self.root.join(name))? == *recorded;
        }
        if unchanged {
            Ok(())
        } else {
            verify_with_header(&self.root, &self.header_sha256)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture engine root whose receipt is consistent with its bytes.
    /// Returns the digest of the fixture adapter header, which stands in for
    /// the pinned constant.
    fn write_engine(directory: &Path) -> String {
        std::fs::create_dir_all(directory.join("Networking")).unwrap();
        let contents = [
            (ARTIFACTS[0], b"adapter".to_vec()),
            (ARTIFACTS[1], vec![1_u8; 70_000]),
            (ARTIFACTS[2], vec![2_u8; 130_000]),
        ];
        let mut receipt = String::new();
        for (name, bytes) in &contents {
            std::fs::write(directory.join(name), bytes).unwrap();
            receipt.push_str(&format!("{:x}  {name}\n", Sha256::digest(bytes)));
        }
        std::fs::write(directory.join(RECEIPT), receipt).unwrap();
        format!("{:x}", Sha256::digest(b"adapter"))
    }

    #[test]
    fn pin_rechecks_cheaply_and_still_refuses_a_changed_artifact() {
        let directory = tempfile::tempdir().unwrap();
        let header = write_engine(directory.path());
        // The real constant is not the fixture header, so the public entry
        // point refuses this root; the pinned-header path is what is tested.
        assert!(EnginePin::verify(directory.path())
            .unwrap_err()
            .contains("pinned adapter"));
        let pin = EnginePin::verify_with_header(directory.path(), &header).unwrap();
        assert!(pin.recheck().is_ok());

        // Same bytes rewritten: identity changes, the slow path hashes, passes.
        let path = directory.path().join(ARTIFACTS[1]);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(pin.recheck().is_ok());

        // Different bytes (one appended, so the identity differs even when the
        // file system's timestamp tick has not advanced): the slow path refuses.
        let mut changed = bytes.clone();
        changed.push(0xff);
        std::fs::write(&path, &changed).unwrap();
        assert!(pin.recheck().unwrap_err().contains("artifact changed"));
        std::fs::write(&path, &bytes).unwrap();
        assert!(pin.recheck().is_ok());

        // A replaced receipt is refused as well.
        std::fs::write(directory.path().join(RECEIPT), "").unwrap();
        assert!(pin
            .recheck()
            .unwrap_err()
            .contains("invalid hybrid engine receipt"));
        std::fs::remove_file(directory.path().join(RECEIPT)).unwrap();
        assert!(pin
            .recheck()
            .unwrap_err()
            .contains("missing hybrid engine artifact"));
    }

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
