//! Crash recovery at the only dangerous FROST provisioning boundary: after
//! recipient-encrypted round-two packages exist but before every node has
//! durably finalized the common group key.

use qomm_transport::frost_coordinator::{finalize_frost_dkg, prepare_frost_dkg};
use qomm_transport::proof_client::ProofPartyRpc;
use qomm_transport::proof_party::{ProofParty, ProofPartyConfig, ProofRequest};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct LocalParty {
    node: u16,
    root: PathBuf,
    party: ProofParty,
    next_id: u64,
    health_enabled: bool,
}

impl LocalParty {
    fn config(node: u16, root: &Path) -> ProofPartyConfig {
        ProofPartyConfig {
            recipient_opening_keys: Vec::new(),
            node,
            allowed_root: root.to_path_buf(),
            state_file: root.join(format!("node-{node}.qps")),
            state_passphrase: vec![node as u8 + 1; 32],
            n_mm: 4,
            n_parties: 7,
            threshold: 2,
            amount_bits: 16,
            price_bits: 32,
            remainder_bits: 32,
            complete_quote_proof: true,
            quote_eligibility_bits: 34,
            quote_span_bits: 32,
            trusted_defmi_receipt_public: None,
            allow_health_signing: false,
        }
    }

    fn new(node: u16, root: &Path) -> Self {
        Self::with_health(node, root, false)
    }

    fn with_health(node: u16, root: &Path, health_enabled: bool) -> Self {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = Self::config(node, root);
        config.allow_health_signing = health_enabled;
        Self {
            node,
            root: root.to_path_buf(),
            party: ProofParty::new(config).unwrap(),
            next_id: 1,
            health_enabled,
        }
    }

    fn restart(&mut self) {
        let mut config = Self::config(self.node, &self.root);
        config.allow_health_signing = self.health_enabled;
        self.party = ProofParty::new(config).unwrap();
        self.next_id = 1;
    }
}

impl ProofPartyRpc for LocalParty {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let response = self.party.handle(ProofRequest {
            id,
            method: method.into(),
            params,
        });
        if !response.ok {
            return Err(response
                .error
                .unwrap_or_else(|| "local proof party rejected the request".into()));
        }
        response
            .result
            .ok_or_else(|| "local proof party omitted its result".into())
    }
}

#[test]
fn actual_node_pq_approvals_bind_the_dkg_and_survive_restart() {
    // This is the existing domain-separated health authorization, explicitly
    // enabled for this cryptographic regression. It is not a payment proof.
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use qomm_transport::frost_coordinator::{
        distributed_hybrid_sign, frost_signing_job, read_pq_committee,
    };
    use sha2::{Digest, Sha256};
    let roots = (0..7).map(|_| TempDir::new().unwrap()).collect::<Vec<_>>();
    let mut parties = roots
        .iter()
        .enumerate()
        .map(|(node, root)| LocalParty::with_health(node as u16, root.path(), true))
        .collect::<Vec<_>>();
    let session = [42_u8; 32];
    let first = parties[0]
        .call("frost_identity", json!({"session": hex::encode(session)}))
        .unwrap();
    parties[0].restart();
    assert_eq!(
        first,
        parties[0]
            .call("frost_identity", json!({"session": hex::encode(session)}))
            .unwrap()
    );
    let plan = prepare_frost_dkg(&mut parties, session).unwrap();
    let public = finalize_frost_dkg(&mut parties, &plan).unwrap();
    let policy = read_pq_committee(&mut parties, &public).unwrap();
    assert_eq!(policy.members.len(), 7);
    assert_eq!(policy.threshold, 3);
    let cluster = [43_u8; 32];
    for stage in [1_u8, 2] {
        let message: [u8; 32] = Sha256::new()
            .chain_update(b"QOMM:FROST:HEALTH:v1")
            .chain_update(session)
            .chain_update([stage])
            .chain_update(cluster)
            .finalize()
            .into();
        assert!(
            distributed_hybrid_sign(&mut parties, &[1, 2, 3], &message, &public, &policy).is_err()
        );
        for party in &mut parties[..3] {
            party
                .call(
                    "authorize_health",
                    json!({
                        "signing_job_id": hex::encode(frost_signing_job(&message)),
                        "message": BASE64.encode(message), "cluster_digest": hex::encode(cluster),
                        "stage": if stage == 1 { "pre-restart" } else { "post-restart" },
                    }),
                )
                .unwrap();
        }
        let signed =
            distributed_hybrid_sign(&mut parties, &[1, 2, 3], &message, &public, &policy).unwrap();
        public
            .verifying_key()
            .verify(&message, &signed.classical)
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        policy.verify(&signed.pq, &message, now).unwrap();
        let mut tampered = signed.pq;
        tampered.signatures[0].signature[0] ^= 1;
        assert!(policy.verify(&tampered, &message, now).is_err());
        for party in &mut parties {
            party.restart();
        }
        assert_eq!(policy, read_pq_committee(&mut parties, &public).unwrap());
        assert!(
            distributed_hybrid_sign(&mut parties, &[1, 2, 3], &message, &public, &policy).is_err()
        );
    }
}

fn configure_and_confirm(parties: &mut [LocalParty], session: [u8; 32]) {
    let entries = Value::Array(
        parties
            .iter_mut()
            .map(|party| {
                party
                    .call("frost_identity", json!({"session": hex::encode(session)}))
                    .unwrap()
            })
            .collect(),
    );
    let confirmations = Value::Array(
        parties
            .iter_mut()
            .map(|party| {
                let response = party
                    .call(
                        "frost_configure_peers",
                        json!({
                            "session": hex::encode(session),
                            "entries": entries.clone(),
                        }),
                    )
                    .unwrap();
                json!({
                    "party": response["party"].clone(),
                    "confirmation": response["confirmation"].clone(),
                    "pq_confirmation": response["pq_confirmation"].clone(),
                })
            })
            .collect(),
    );
    for party in parties {
        party
            .call(
                "frost_confirm_peers",
                json!({"confirmations": confirmations.clone()}),
            )
            .unwrap();
    }
}

fn assert_ready(parties: &mut [LocalParty]) {
    for party in parties {
        let health = party.call("health", Value::Null).unwrap();
        assert_eq!(health["frost_ready"], true);
        assert_eq!(health["frost_peer_manifest_persisted"], false);
        assert_eq!(health["frost_dkg_round1_persisted"], false);
        assert_eq!(health["frost_dkg_round2_persisted"], false);
    }
}

#[test]
fn durable_signing_state_rejects_a_changed_proof_configuration() {
    let root = TempDir::new().unwrap();
    let party = LocalParty::new(0, root.path());
    let stable_identity = party.party.instance_id();
    drop(party);

    let mut changed = LocalParty::config(0, root.path());
    changed.complete_quote_proof = false;
    let error = ProofParty::new(changed).err().unwrap();
    assert!(error.contains("security configuration"));

    let restored = ProofParty::new(LocalParty::config(0, root.path())).unwrap();
    assert_eq!(restored.instance_id(), stable_identity);
}

#[test]
fn coordinator_can_restart_before_every_node_reaches_round_two() {
    let root = TempDir::new().unwrap();
    let mut parties = (0_u16..7)
        .map(|node| LocalParty::new(node, root.path()))
        .collect::<Vec<_>>();
    let session = [0x31; 32];
    configure_and_confirm(&mut parties, session);

    // Only part of the committee has emitted a durable round-one package when
    // the coordinator and two different-stage nodes disappear.
    for party in parties.iter_mut().take(3) {
        party.call("frost_dkg_round1", json!({})).unwrap();
    }
    parties[0].restart();
    parties[5].restart();

    let plan = prepare_frost_dkg(&mut parties, session).unwrap();
    finalize_frost_dkg(&mut parties, &plan).unwrap();
    assert_ready(&mut parties);
}

#[test]
fn coordinator_reconstructs_a_missing_journal_after_partial_round_two() {
    let root = TempDir::new().unwrap();
    let mut parties = (0_u16..7)
        .map(|node| LocalParty::new(node, root.path()))
        .collect::<Vec<_>>();
    let session = [0x32; 32];
    configure_and_confirm(&mut parties, session);
    let broadcasts = Value::Array(
        parties
            .iter_mut()
            .map(|party| party.call("frost_dkg_round1", json!({})).unwrap())
            .collect(),
    );

    // Four nodes persisted recipient-encrypted round two, but the coordinator
    // died before it could write a complete journal.  A fresh coordinator must
    // recover the same broadcasts and encrypted packages from the nodes.
    for party in parties.iter_mut().take(4) {
        party
            .call(
                "frost_dkg_round2",
                json!({"broadcasts": broadcasts.clone()}),
            )
            .unwrap();
    }
    parties[1].restart();
    parties[5].restart();

    let plan = prepare_frost_dkg(&mut parties, session).unwrap();
    finalize_frost_dkg(&mut parties, &plan).unwrap();
    assert_ready(&mut parties);
}

#[test]
fn journaled_round_two_survives_node_and_coordinator_restart() {
    let root = TempDir::new().unwrap();
    let mut parties = (0_u16..7)
        .map(|node| LocalParty::new(node, root.path()))
        .collect::<Vec<_>>();
    let session = [0x42; 32];
    let plan = prepare_frost_dkg(&mut parties, session).unwrap();

    let first_signed_wire = parties[0]
        .call(
            "frost_dkg_round2",
            json!({"broadcasts": plan.broadcasts.clone()}),
        )
        .unwrap();
    parties[0].restart();
    let reopened_signed_wire = parties[0]
        .call(
            "frost_dkg_round2",
            json!({"broadcasts": plan.broadcasts.clone()}),
        )
        .unwrap();
    assert_eq!(reopened_signed_wire, first_signed_wire);

    // Three different proof processes disappear after emitting their encrypted
    // packages. Their encrypted state must carry enough information to finish
    // the exact journaled transcript, without another round-one secret.
    for node in [0_usize, 3, 6] {
        parties[node].restart();
    }
    let public = finalize_frost_dkg(&mut parties, &plan).unwrap();

    // A coordinator may lose one or more final replies. Replaying the exact
    // journal is idempotent, while every node returns the same public package.
    let replayed = finalize_frost_dkg(&mut parties, &plan).unwrap();
    assert_eq!(public.serialize().unwrap(), replayed.serialize().unwrap());
    assert_ready(&mut parties);
    for party in &mut parties {
        let health = party.call("health", Value::Null).unwrap();
        assert!(health["state_generation"].as_u64().unwrap() >= 3);
    }
}

#[test]
fn hybrid_dkg_envelopes_reject_downgrade_and_sender_substitution_before_commit() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use qomm_transport::selective_disclosure::WinnerEnvelope;
    let root = TempDir::new().unwrap();
    let mut parties = (0_u16..7)
        .map(|node| LocalParty::new(node, root.path()))
        .collect::<Vec<_>>();
    let plan = prepare_frost_dkg(&mut parties, [0x55; 32]).unwrap();
    for incoming in &plan.incoming {
        for record in incoming {
            let envelope = WinnerEnvelope::decode(
                &BASE64.decode(record["envelope"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            assert_eq!(envelope.version, 3);
            assert_eq!(envelope.kem_ciphertext.len(), 1120);
            assert_eq!(envelope.pq_signature.len(), 3309);
        }
    }
    let call = |party: &mut LocalParty, incoming: &[Value]| {
        party.call(
            "frost_dkg_finalize",
            json!({"broadcasts": plan.broadcasts.clone(), "incoming": incoming}),
        )
    };
    let mut malformed = plan.incoming[0].clone();
    malformed[0].as_object_mut().unwrap().remove("envelope");
    malformed[0]["ciphertext"] = json!("classical-only record");
    assert!(call(&mut parties[0], &malformed).is_err());
    malformed = plan.incoming[0].clone();
    let mut envelope = WinnerEnvelope::decode(
        &BASE64
            .decode(malformed[0]["envelope"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let attacker = SigningKey::from_bytes(&[0x77; 32]);
    envelope.taker_public = attacker.verifying_key().to_bytes();
    envelope.signature = attacker.sign(&envelope.unsigned().unwrap());
    malformed[0]["envelope"] = json!(BASE64.encode(envelope.encode().unwrap()));
    assert!(call(&mut parties[0], &malformed)
        .unwrap_err()
        .contains("signature"));
    assert_eq!(
        parties[0].call("health", Value::Null).unwrap()["frost_ready"],
        false
    );
    parties[0].restart();
    finalize_frost_dkg(&mut parties, &plan).unwrap();
    assert_ready(&mut parties);
}
