use ed25519_dalek::{Signer as _, SigningKey};
use qomm_transport::selective_disclosure::{
    open_if_winner, seal_for_winner, WinnerPrivateKey, WinnerPublicKey, WinnerSenderAuth,
    AUTH_SUITE, CLEAR_BYTES, DOMAIN, VERSION,
};
use zkfmi_crypto::{
    backend::MlDsa65Signer,
    key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
    suite::{Suite, SuiteId},
    traits::Signer as _,
};

struct TakerAuth {
    identity: SigningKey,
    pq: MlDsa65Signer,
    record: KeyRecord,
}

fn taker_auth(seed: u8) -> TakerAuth {
    let identity = SigningKey::from_bytes(&[seed; 32]);
    let pq = MlDsa65Signer::from_seed(&[seed.wrapping_add(1); 32]);
    let record = KeyRecord {
        participant_id: ParticipantId::new(format!("taker-{seed}")).unwrap(),
        key_id: KeyId::new(format!("taker-{seed}-settlement-v1")).unwrap(),
        suite: AUTH_SUITE,
        key_version: 1,
        purpose: KeyPurpose::SettlementInstruction,
        public_key: pq.public_key(),
        not_before: 1,
        not_after: 1_000,
        revoked_at: None,
        rotation_proof: None,
        dekyx_binding: None,
    };
    TakerAuth {
        identity,
        pq,
        record,
    }
}

#[test]
fn only_the_winner_opens_a_fixed_size_envelope() {
    let taker = taker_auth(1);
    let winner = WinnerPrivateKey::generate().unwrap();
    let loser = WinnerPrivateKey::generate().unwrap();
    let quote = [4_u8; 32];
    let envelope = seal_for_winner(
        "maker-7",
        &winner.public_key().unwrap(),
        b"settle instruction",
        b"slot:42",
        quote,
        &taker.identity,
        &taker.pq,
    )
    .unwrap();
    assert_eq!(envelope.version, VERSION);
    assert_eq!(envelope.ciphertext.len(), CLEAR_BYTES + 16);
    assert_eq!(envelope.pq_signature.len(), 3_309);
    assert_eq!(
        open_if_winner(
            &envelope,
            "maker-7",
            &[loser],
            b"slot:42",
            quote,
            WinnerSenderAuth {
                ed25519: &taker.identity.verifying_key(),
                pq_key: &taker.record,
                valid_at: 10,
            },
        )
        .unwrap(),
        None
    );
    assert_eq!(
        open_if_winner(
            &envelope,
            "maker-7",
            &[winner],
            b"slot:42",
            quote,
            WinnerSenderAuth {
                ed25519: &taker.identity.verifying_key(),
                pq_key: &taker.record,
                valid_at: 10,
            },
        )
        .unwrap(),
        Some(b"settle instruction".to_vec())
    );
}

#[test]
fn public_envelope_does_not_name_the_winner_or_key() {
    let taker = taker_auth(2);
    let winner = WinnerPrivateKey::generate().unwrap();
    let public = winner.public_key().unwrap().raw_public_key().unwrap();
    let envelope = seal_for_winner(
        "secret-maker-name",
        &winner.public_key().unwrap(),
        b"x",
        b"market",
        [7; 32],
        &taker.identity,
        &taker.pq,
    )
    .unwrap();
    let unsigned = envelope.unsigned().unwrap();
    assert!(!unsigned
        .windows(b"secret-maker-name".len())
        .any(|part| part == b"secret-maker-name"));
    assert!(!unsigned.windows(public.len()).any(|part| part == public));
}

#[test]
fn context_quote_roster_and_oversize_tampering_are_refused() {
    let taker = taker_auth(3);
    let winner = WinnerPrivateKey::generate().unwrap();
    let envelope = seal_for_winner(
        "m",
        &winner.public_key().unwrap(),
        b"x",
        b"market",
        [8; 32],
        &taker.identity,
        &taker.pq,
    )
    .unwrap();
    assert!(open_if_winner(
        &envelope,
        "m",
        std::slice::from_ref(&winner),
        b"other",
        [8; 32],
        WinnerSenderAuth {
            ed25519: &taker.identity.verifying_key(),
            pq_key: &taker.record,
            valid_at: 10,
        },
    )
    .unwrap_err()
    .contains("context"));
    let stranger = taker_auth(4);
    assert!(open_if_winner(
        &envelope,
        "m",
        std::slice::from_ref(&winner),
        b"market",
        [8; 32],
        WinnerSenderAuth {
            ed25519: &stranger.identity.verifying_key(),
            pq_key: &taker.record,
            valid_at: 10,
        },
    )
    .unwrap_err()
    .contains("Ed25519"));
    assert!(open_if_winner(
        &envelope,
        "m",
        std::slice::from_ref(&winner),
        b"market",
        [8; 32],
        WinnerSenderAuth {
            ed25519: &taker.identity.verifying_key(),
            pq_key: &stranger.record,
            valid_at: 10,
        },
    )
    .unwrap_err()
    .contains("signature"));
    assert!(seal_for_winner(
        "m",
        &WinnerPrivateKey::generate().unwrap().public_key().unwrap(),
        &vec![0; CLEAR_BYTES],
        b"market",
        [8; 32],
        &taker.identity,
        &taker.pq,
    )
    .unwrap_err()
    .contains("exceeds"));
}

#[test]
fn old_private_key_opens_during_rotation_overlap() {
    let taker = taker_auth(5);
    let old = WinnerPrivateKey::generate().unwrap();
    let new = WinnerPrivateKey::generate().unwrap();
    let envelope = seal_for_winner(
        "m",
        &old.public_key().unwrap(),
        b"rotate",
        b"market",
        [9; 32],
        &taker.identity,
        &taker.pq,
    )
    .unwrap();
    assert_eq!(
        open_if_winner(
            &envelope,
            "m",
            &[new, old],
            b"market",
            [9; 32],
            WinnerSenderAuth {
                ed25519: &taker.identity.verifying_key(),
                pq_key: &taker.record,
                valid_at: 10,
            },
        )
        .unwrap(),
        Some(b"rotate".to_vec())
    );
}

#[test]
fn hybrid_delivery_refuses_downgrade_and_requires_all_components() {
    let taker = taker_auth(6);
    let winner = WinnerPrivateKey::from_seed(&[31; 96]);
    let envelope = seal_for_winner(
        "m",
        &winner.public_key().unwrap(),
        b"private",
        b"market",
        [8; 32],
        &taker.identity,
        &taker.pq,
    )
    .unwrap();
    let open = |candidate: &qomm_transport::selective_disclosure::WinnerEnvelope,
                key: &KeyRecord,
                now: u64| {
        open_if_winner(
            candidate,
            "m",
            std::slice::from_ref(&winner),
            b"market",
            [8; 32],
            WinnerSenderAuth {
                ed25519: &taker.identity.verifying_key(),
                pq_key: key,
                valid_at: now,
            },
        )
    };
    assert_eq!(envelope.kem_ciphertext.len(), 1120);
    let encoded = envelope.encode().unwrap();
    let decoded = qomm_transport::selective_disclosure::WinnerEnvelope::decode(&encoded).unwrap();
    assert_eq!(decoded.encode().unwrap(), encoded);
    assert_eq!(
        open(&decoded, &taker.record, 10).unwrap(),
        Some(b"private".to_vec())
    );
    assert!(
        qomm_transport::selective_disclosure::WinnerEnvelope::decode(&encoded[..encoded.len() - 1])
            .is_err()
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(qomm_transport::selective_disclosure::WinnerEnvelope::decode(&trailing).is_err());
    let mut legacy = encoded.clone();
    legacy[..DOMAIN.len()].copy_from_slice(b"QOMM:WINNER:ENVELOPE:v2");
    legacy[DOMAIN.len()] = 2;
    assert!(
        qomm_transport::selective_disclosure::WinnerEnvelope::decode(&legacy)
            .unwrap_err()
            .contains("v2")
    );
    assert_eq!(
        winner.public_key().unwrap().raw_public_key().unwrap().len(),
        1216
    );
    assert!(WinnerPublicKey::from_raw(&[7; 32]).is_err());

    let mut altered = envelope.clone();
    altered.signature = ed25519_dalek::Signature::from_bytes(&[0; 64]);
    assert!(open(&altered, &taker.record, 10).is_err());
    altered = envelope.clone();
    altered.pq_signature[0] ^= 1;
    assert!(open(&altered, &taker.record, 10).is_err());
    altered = envelope.clone();
    altered.pq_signature.pop();
    assert!(open(&altered, &taker.record, 10).is_err());
    altered = envelope.clone();
    altered.pq_signature.push(0);
    assert!(open(&altered, &taker.record, 10).is_err());

    for at in [0, 32] {
        let mut altered = envelope.clone();
        altered.kem_ciphertext[at] ^= 1;
        // Re-sign both components to reach the actual KEM/AEAD checks.
        let unsigned = altered.unsigned().unwrap();
        altered.signature = taker.identity.sign(&unsigned);
        altered.pq_signature = taker
            .pq
            .sign(KeyPurpose::SettlementInstruction, &unsigned)
            .unwrap();
        assert_eq!(open(&altered, &taker.record, 10).unwrap(), None);
    }
    altered = envelope.clone();
    altered.version = 2;
    assert!(open(&altered, &taker.record, 10).is_err());
    altered = envelope.clone();
    altered.suite = Suite::new(SuiteId::MlKem768);
    assert!(open(&altered, &taker.record, 10).is_err());
    altered = envelope.clone();
    altered.kem_ciphertext.truncate(32);
    assert!(open(&altered, &taker.record, 10).is_err());

    let mut expired = taker.record.clone();
    expired.not_after = 10;
    assert!(open(&envelope, &expired, 10).is_err());
    let mut not_yet_valid = taker.record.clone();
    not_yet_valid.not_before = 11;
    assert!(open(&envelope, &not_yet_valid, 10).is_err());
    let mut revoked = taker.record.clone();
    revoked.revoked_at = Some(10);
    assert!(open(&envelope, &revoked, 10).is_err());
    let mut wrong_purpose = taker.record.clone();
    wrong_purpose.purpose = KeyPurpose::Quote;
    assert!(open(&envelope, &wrong_purpose, 10).is_err());

    let mut wrong_recipient_seed = [31; 96];
    wrong_recipient_seed[32] ^= 1;
    assert_eq!(
        open_if_winner(
            &envelope,
            "m",
            &[WinnerPrivateKey::from_seed(&wrong_recipient_seed)],
            b"market",
            [8; 32],
            WinnerSenderAuth {
                ed25519: &taker.identity.verifying_key(),
                pq_key: &taker.record,
                valid_at: 10,
            },
        )
        .unwrap(),
        None
    );
}
