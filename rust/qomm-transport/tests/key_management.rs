use qomm_transport::key_management::{
    create_ca, issue_mutual_tls_certificate, write_tls_bundle, EncryptedKeyStore, KeyKind,
};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn store(directory: &tempfile::TempDir) -> EncryptedKeyStore {
    let vault = EncryptedKeyStore::new(
        directory.path().join("keys.qks"),
        b"correct horse battery staple",
    )
    .unwrap();
    vault.initialize().unwrap();
    vault
}

#[test]
fn ml_dsa_authority_restores_rotates_and_rejects_live_retired_keys() {
    use zkfmi_crypto::{
        key::KeyPurpose,
        traits::{Signer, Verifier},
    };
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let first = vault
        .generate("admin_pq", KeyKind::MlDsa65, 100, 1000, BTreeMap::new())
        .unwrap();
    let key = vault.private_key(&first, 101, false).unwrap();
    let public = key.ml_dsa65().unwrap().public_key();
    let signature = key
        .ml_dsa65()
        .unwrap()
        .sign(KeyPurpose::Attestation, b"approval")
        .unwrap();
    drop(key);
    drop(vault);
    let restored = EncryptedKeyStore::new(
        directory.path().join("keys.qks"),
        b"correct horse battery staple",
    )
    .unwrap();
    assert_eq!(
        restored
            .private_key(&first, 102, false)
            .unwrap()
            .ml_dsa65()
            .unwrap()
            .public_key(),
        public
    );
    zkfmi_crypto::backend::MlDsa65Verifier
        .verify(KeyPurpose::Attestation, &public, b"approval", &signature)
        .unwrap();
    let second = restored
        .rotate("admin_pq", KeyKind::MlDsa65, 200, 1000, BTreeMap::new())
        .unwrap();
    assert_ne!(second, first);
    assert!(restored.private_key(&first, 201, false).is_err());
    assert!(restored.private_key(&first, 201, true).is_ok());
    assert!(restored
        .rotate("admin_pq", KeyKind::Ed25519, 202, 1000, BTreeMap::new())
        .is_err());
    restored.revoke(&first, 203, "retired authority").unwrap();
    assert!(restored.private_key(&first, 204, true).is_err());
}

#[test]
fn hybrid_key_restore_rotation_revocation_and_downgrade_are_enforced() {
    use ed25519_dalek::SigningKey;
    use qomm_transport::selective_disclosure::{open_if_winner, seal_for_winner, WinnerSenderAuth};
    use rand_core::OsRng;
    use zkfmi_crypto::{
        backend::MlDsa65Signer,
        key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
        suite::{Suite, SuiteId},
        traits::Signer,
    };
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let purpose = "maker:m1:hybrid-delivery";
    let old = vault
        .generate(purpose, KeyKind::HybridKem, 100, 1000, BTreeMap::new())
        .unwrap();
    let taker = SigningKey::generate(&mut OsRng);
    let pq = MlDsa65Signer::generate().unwrap();
    let pq_key = KeyRecord {
        participant_id: ParticipantId::new("key-management-test-taker").unwrap(),
        key_id: KeyId::new("key-management-test-settlement-v1").unwrap(),
        suite: Suite::new(SuiteId::MlDsa65),
        key_version: 1,
        purpose: KeyPurpose::SettlementInstruction,
        public_key: pq.public_key(),
        not_before: 100,
        not_after: 1_000,
        revoked_at: None,
        rotation_proof: None,
        dekyx_binding: None,
    };
    let old_public = vault
        .private_key(&old, 101, false)
        .unwrap()
        .hybrid_kem()
        .unwrap()
        .public_key()
        .unwrap();
    let envelope = seal_for_winner(
        "m1",
        &old_public,
        b"settle",
        b"market",
        [5; 32],
        &taker,
        &pq,
    )
    .unwrap();
    assert!(vault.private_key(&old, 99, false).is_err());
    let new = vault
        .rotate(purpose, KeyKind::HybridKem, 200, 1000, BTreeMap::new())
        .unwrap();
    let restored = EncryptedKeyStore::new(
        directory.path().join("keys.qks"),
        b"correct horse battery staple",
    )
    .unwrap();
    let keys = restored
        .private_keys_for(purpose, 201, true)
        .unwrap()
        .into_iter()
        .map(|key| key.hybrid_kem().unwrap().clone())
        .collect::<Vec<_>>();
    assert_eq!(
        open_if_winner(
            &envelope,
            "m1",
            &keys,
            b"market",
            [5; 32],
            WinnerSenderAuth {
                ed25519: &taker.verifying_key(),
                pq_key: &pq_key,
                valid_at: 201,
            },
        )
        .unwrap(),
        Some(b"settle".to_vec())
    );
    assert!(restored.private_key(&old, 201, false).is_err());
    assert!(restored
        .rotate(purpose, KeyKind::X25519, 202, 1000, BTreeMap::new())
        .is_err());
    restored.revoke(&old, 202, "rotation complete").unwrap();
    assert!(restored.private_key(&old, 203, true).is_err());
    assert!(restored.private_key(&new, 1201, false).is_err());
    let keys = restored
        .private_keys_for(purpose, 203, true)
        .unwrap()
        .into_iter()
        .map(|key| key.hybrid_kem().unwrap().clone())
        .collect::<Vec<_>>();
    assert_eq!(
        open_if_winner(
            &envelope,
            "m1",
            &keys,
            b"market",
            [5; 32],
            WinnerSenderAuth {
                ed25519: &taker.verifying_key(),
                pq_key: &pq_key,
                valid_at: 203,
            },
        )
        .unwrap(),
        None
    );
}

#[test]
fn private_material_is_encrypted_atomic_and_mode_0600() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let key_id = vault
        .generate(
            "maker:m1:encryption",
            KeyKind::X25519,
            100,
            365 * 24 * 3600,
            BTreeMap::new(),
        )
        .unwrap();
    let raw = fs::read(directory.path().join("keys.qks")).unwrap();
    let secret = vault
        .private_key(&key_id, 101, false)
        .unwrap()
        .raw_private_key()
        .unwrap();
    assert!(!raw.windows(secret.len()).any(|window| window == secret));
    assert_eq!(
        fs::metadata(directory.path().join("keys.qks"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(directory.path().join("keys.qks.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let wrong =
        EncryptedKeyStore::new(directory.path().join("keys.qks"), b"wrong passphrase").unwrap();
    assert!(wrong.snapshot().unwrap_err().contains("authentication"));
}

#[test]
fn anonymous_kyb_scalar_is_encrypted_and_only_its_ristretto_point_is_public() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let key_id = vault
        .generate(
            "kyb_entity",
            KeyKind::Ristretto,
            100,
            365 * 24 * 3600,
            BTreeMap::new(),
        )
        .unwrap();
    let stored = vault.private_key(&key_id, 101, false).unwrap();
    let secret = stored.ristretto_scalar().unwrap();
    assert_ne!(*secret, curve25519_dalek::scalar::Scalar::ZERO);
    let public = vault
        .snapshot()
        .unwrap()
        .keys
        .into_iter()
        .find(|record| record.key_id == key_id)
        .unwrap();
    assert_eq!(public.kind, KeyKind::Ristretto);
    assert!(!serde_json::to_string(&public).unwrap().contains("private"));
    let raw = fs::read(directory.path().join("keys.qks")).unwrap();
    assert!(!raw.windows(32).any(|window| window == secret.as_bytes()));
}

#[test]
fn rotation_overlap_is_explicit_and_revocation_is_final() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let old = vault
        .generate(
            "maker:m1:encryption",
            KeyKind::X25519,
            100,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    let new = vault
        .rotate(
            "maker:m1:encryption",
            KeyKind::X25519,
            200,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(
        vault
            .private_keys_for("maker:m1:encryption", 201, false)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vault
            .private_keys_for("maker:m1:encryption", 201, true)
            .unwrap()
            .len(),
        2
    );
    assert!(vault
        .private_key(&old, 201, false)
        .unwrap_err()
        .contains("active"));
    vault
        .revoke(&new, 202, "operator credential compromise")
        .unwrap();
    assert!(vault
        .private_key(&new, 203, false)
        .unwrap_err()
        .contains("revoked"));
}

#[test]
fn public_registry_is_signed_and_contains_no_private_field() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let signer = vault
        .generate(
            "registry-signing",
            KeyKind::HybridSignature,
            100,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    vault
        .generate(
            "maker:m1:encryption",
            KeyKind::X25519,
            100,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    let manifest = vault.public_manifest(&signer, 102).unwrap();
    let signing = vault.private_key(&signer, 102, false).unwrap();
    assert!(manifest.verify(&signing.hybrid_signature().unwrap().verifying_key()));
    let encoded = serde_json::to_string(&manifest.records).unwrap();
    assert!(!encoded.contains("private"));
    let mut moved = manifest.clone();
    moved.generation += 1;
    assert!(!moved.verify(&signing.hybrid_signature().unwrap().verifying_key()));
}

#[test]
fn tls_certificates_require_the_ca_and_private_files_are_not_world_readable() {
    let directory = tempfile::tempdir().unwrap();
    let (ca_key, ca_cert) = create_ca("QOMM test CA", 3650).unwrap();
    let (node_key, node_cert) =
        issue_mutual_tls_certificate(&ca_key, &ca_cert, "node-0", &["node-0"], &["127.0.0.1"], 30)
            .unwrap();
    assert!(zkfmi_crypto::tls::certificate_uses_pqc_authentication(
        &ca_cert
    ));
    assert!(zkfmi_crypto::tls::certificate_uses_pqc_authentication(
        &node_cert
    ));
    assert!(node_cert.verify(&ca_key).unwrap());
    let (key, cert, ca) = write_tls_bundle(
        directory.path().join("pki"),
        "node-0",
        &node_key,
        &node_cert,
        &ca_cert,
    )
    .unwrap();
    assert_eq!(
        fs::metadata(key).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(cert).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(ca).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(
        node_cert.issuer_name().to_der().unwrap(),
        ca_cert.subject_name().to_der().unwrap()
    );
}

#[test]
fn weak_passphrase_and_relaxed_permissions_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    assert!(
        EncryptedKeyStore::new(directory.path().join("keys"), b"short")
            .unwrap_err()
            .contains("12")
    );
    let vault = store(&directory);
    fs::set_permissions(
        directory.path().join("keys.qks"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(vault.snapshot().unwrap_err().contains("600"));
}

#[test]
fn node_local_csr_rejects_classical_keys_and_mismatched_authorities() {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::x509::{X509NameBuilder, X509Req};
    use qomm_transport::key_management::{
        create_mutual_tls_request, issue_mutual_tls_certificate_from_csr,
    };
    let (ca_key, ca) = create_ca("pqc-ca", 1).unwrap();
    let (node_key, request) = create_mutual_tls_request("node-0").unwrap();
    let cert = issue_mutual_tls_certificate_from_csr(
        &ca_key,
        &ca,
        &request,
        "node-0",
        &["node-0"],
        &[],
        1,
    )
    .unwrap();
    assert!(node_key.public_eq(&cert.public_key().unwrap()));
    assert!(zkfmi_crypto::tls::certificate_uses_pqc_authentication(
        &cert
    ));
    let (other_ca, _) = create_ca("other-ca", 1).unwrap();
    assert!(issue_mutual_tls_certificate_from_csr(
        &other_ca,
        &ca,
        &request,
        "node-0",
        &["node-0"],
        &[],
        1,
    )
    .is_err());
    assert!(issue_mutual_tls_certificate_from_csr(
        &ca_key,
        &ca,
        &request,
        "node-1",
        &["node-1"],
        &[],
        1,
    )
    .is_err());

    let classical = PKey::generate_ed25519().unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "node-0").unwrap();
    let mut request = X509Req::builder().unwrap();
    request.set_version(0).unwrap();
    request.set_subject_name(&name.build()).unwrap();
    request.set_pubkey(&classical).unwrap();
    request.sign(&classical, MessageDigest::null()).unwrap();
    assert!(issue_mutual_tls_certificate_from_csr(
        &ca_key,
        &ca,
        &request.build(),
        "node-0",
        &["node-0"],
        &[],
        1,
    )
    .is_err());
}

#[test]
fn application_signature_custody_survives_restore_and_closes_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let vault = store(&directory);
    let first = vault
        .generate(
            "application",
            KeyKind::HybridSignature,
            100,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    let stored = vault.private_key(&first, 101, false).unwrap();
    let key = stored.hybrid_signature().unwrap();
    let public = key.verifying_key();
    let signature = key.try_sign(b"binding").unwrap();
    assert!(stored.raw_private_key().is_err());
    drop(stored);
    drop(vault);
    let restored = EncryptedKeyStore::new(
        directory.path().join("keys.qks"),
        b"correct horse battery staple",
    )
    .unwrap();
    let stored = restored.private_key(&first, 102, false).unwrap();
    assert_eq!(stored.hybrid_signature().unwrap().verifying_key(), public);
    public.verify(b"binding", &signature).unwrap();
    let second = restored
        .rotate(
            "application",
            KeyKind::HybridSignature,
            200,
            1000,
            BTreeMap::new(),
        )
        .unwrap();
    assert_ne!(first, second);
    assert!(restored.private_key(&first, 201, false).is_err());
    assert!(restored.private_key(&first, 201, true).is_ok());
    assert!(restored
        .rotate("application", KeyKind::Ed25519, 202, 1000, BTreeMap::new())
        .is_err());
    restored.revoke(&first, 203, "retired").unwrap();
    assert!(restored.private_key(&first, 204, true).is_err());
}

#[test]
fn application_key_cli_generates_into_existing_encrypted_custody() {
    let directory = tempfile::tempdir().unwrap();
    let passphrase = directory.path().join("passphrase");
    fs::write(&passphrase, b"fixture-only custody phrase").unwrap();
    fs::set_permissions(&passphrase, fs::Permissions::from_mode(0o600)).unwrap();
    let path = directory.path().join("keys.qks");
    let invoke = |arguments: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_qomm_key_tool"))
            .arg(&path)
            .arg(&passphrase)
            .args(arguments)
            .output()
            .unwrap()
    };
    assert!(invoke(&["init"]).status.success());
    assert!(!invoke(&["init"]).status.success());
    let result = invoke(&["generate", "application", "100", "1000"]);
    assert!(result.status.success());
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    let store = EncryptedKeyStore::new(&path, b"fixture-only custody phrase").unwrap();
    let key = store
        .private_key(value["key_id"].as_str().unwrap(), 101, false)
        .unwrap();
    let signer = key.hybrid_signature().unwrap();
    signer
        .verifying_key()
        .verify(
            b"restored CLI key",
            &signer.try_sign(b"restored CLI key").unwrap(),
        )
        .unwrap();
    fs::set_permissions(&passphrase, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!invoke(&["public"]).status.success());
}
