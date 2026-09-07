//! Node-local PQ signing state and initial committee enrollment.
//! The bootstrap identity is cryptographic, not a verified DeKYX entity.

use super::*;
use zkfmi_crypto::{
    key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
    quorum::{QuorumMember, QuorumPolicy, SUITE},
    suite::Version,
    traits::Signer,
};

pub(super) fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock precedes Unix epoch".into())
}

pub(super) fn initial_record(identity: &SigningKey, public: Vec<u8>) -> Result<KeyRecord, String> {
    let created = now()?;
    // Initial node keys have a bounded one-year lease. Re-enrollment and
    // rotation must update the trusted committee before this lease expires.
    Ok(KeyRecord {
        participant_id: ParticipantId::new(format!(
            "proof-node:{}",
            hex::encode(identity.verifying_key().to_bytes())
        ))
        .map_err(|error| error.to_string())?,
        key_id: KeyId::new(format!("mldsa65:{}", hex::encode(Sha256::digest(&public))))
            .map_err(|error| error.to_string())?,
        suite: SUITE,
        key_version: 1,
        purpose: KeyPurpose::SettlementInstruction,
        public_key: public,
        not_before: created,
        not_after: created
            .checked_add(365 * 24 * 60 * 60)
            .ok_or("PQ key expiry overflow")?,
        revoked_at: None,
        rotation_proof: None,
        dekyx_binding: None,
    })
}

impl ProofParty {
    pub(super) fn pq_identity_signature(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        let id = hex::encode(Sha256::digest(body));
        if let Some(signature) = self.pq_identity_cache.get(&id) {
            return BASE64
                .decode(signature)
                .map_err(|_| "cached PQ identity signature is malformed".into());
        }
        if self.pq_identity_cache.len() >= 64 {
            return Err("PQ identity attestation cache reached its enrollment bound".into());
        }
        let signature = self
            .pq_signer
            .sign(KeyPurpose::Transport, body)
            .map_err(|error| error.to_string())?;
        self.pq_identity_cache.insert(id, BASE64.encode(&signature));
        // ML-DSA is randomized. Persist the exact public attestation so retries
        // after a crash reproduce the original peer-manifest digest.
        self.persist()?;
        Ok(signature)
    }

    pub(super) fn make_pq_committee(
        &self,
        peers: &PendingPeers,
        public: &[u8],
    ) -> Result<QuorumPolicy, String> {
        let policy = QuorumPolicy {
            version: Version::V1,
            // The existing native DKG creates one committee per durable node
            // state. Subsequent epochs require explicit authorized enrollment.
            epoch: 1,
            purpose: KeyPurpose::SettlementInstruction,
            context: [
                b"QOMM:MPC-SETTLEMENT-COMMITTEE:v1".as_slice(),
                &peers.session,
            ]
            .concat(),
            classical_binding: Sha256::digest(public).into(),
            threshold: u16::try_from(self.config.threshold + 1)
                .map_err(|_| "PQ threshold overflow")?,
            members: peers
                .entries
                .iter()
                .map(|entry| QuorumMember {
                    node: entry.party,
                    key: entry.pq_key.clone(),
                })
                .collect(),
        };
        policy.validate().map_err(|error| error.to_string())?;
        Ok(policy)
    }

    pub(super) fn validate_pq_state(&self) -> Result<(), String> {
        self.pq_key.validate().map_err(|error| error.to_string())?;
        if self.pq_key.suite != SUITE
            || self.pq_key.purpose != KeyPurpose::SettlementInstruction
            || self.pq_key.public_key != self.pq_signer.public_key()
            || self.pq_identity_cache.len() > 64
            || self.pq_committee.is_some() != self.frost_public.is_some()
        {
            return Err("stored PQ identity or committee is inconsistent".into());
        }
        if let Some(policy) = &self.pq_committee {
            policy.validate().map_err(|error| error.to_string())?;
            let public = self
                .frost_public
                .as_ref()
                .ok_or("PQ committee lacks its FROST group")?
                .serialize()
                .map_err(|_| "FROST public package cannot be serialized")?;
            let classical_binding: [u8; 32] = Sha256::digest(public).into();
            let session = self
                .frost_session
                .ok_or("PQ committee lacks its DKG session")?;
            if policy.classical_binding != classical_binding
                || policy.context
                    != [b"QOMM:MPC-SETTLEMENT-COMMITTEE:v1".as_slice(), &session].concat()
                || policy.threshold as usize != self.config.threshold + 1
                || policy.members.len() != self.config.n_parties
                || !policy
                    .members
                    .iter()
                    .any(|member| member.node == self.config.node + 1 && member.key == self.pq_key)
            {
                return Err("PQ committee is not bound to this node and classical group".into());
            }
        }
        Ok(())
    }
}
