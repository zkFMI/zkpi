//! Recipient-only recovery of an MPC-created Pedersen opening.
//!
//! Each proof node encrypts only its own Shamir evaluation under the
//! recipient's one-use view key. The coordinator may collect every
//! ciphertext but cannot decrypt one; the recipient decrypts any threshold
//! subset and interpolates the value and blinding at zero. A later caller must
//! still compare the recovered opening with the claim's Pedersen commitment.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;
use std::collections::BTreeSet;
use zkfmi_crypto::{
    hybrid::kem::HybridKemKey,
    sealed::{SealedMessage, SealingPurpose, RECIPIENT_PUBLIC_BYTES},
    traits::KemDecapsulator,
};

use crate::threshold_sigma::{lagrange_at_zero, PartyId};

const ENVELOPE_DOMAIN: &[u8] = b"QOMM:MPC:CLAIM-OPENING-ENVELOPE:v2";

fn share_context(context: &[u8; 32], party: PartyId, recipient_view: &RistrettoPoint) -> [u8; 32] {
    sha2::Sha256::new()
        .chain_update(ENVELOPE_DOMAIN)
        .chain_update(context)
        .chain_update((party as u64).to_be_bytes())
        .chain_update(recipient_view.compress().as_bytes())
        .finalize()
        .into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedOpeningShare {
    pub party: PartyId,
    pub recipient_public: Vec<u8>,
    pub sealed: SealedMessage,
    /// Public reblinding offset bound by the enclosing signed claim.
    pub blinding_adjustment: Scalar,
}

impl EncryptedOpeningShare {
    pub fn validate(&self) -> Result<(), String> {
        if self.party == 0 || self.recipient_public.len() != RECIPIENT_PUBLIC_BYTES {
            return Err("encrypted opening share has an invalid party or recipient key".into());
        }
        self.sealed
            .validate(SealingPurpose::ThresholdOpeningShare, 64)
            .map_err(|e| e.to_string())
    }

    fn opening(
        &self,
        context: &[u8; 32],
        recipient_view: &RistrettoPoint,
        recipient: &HybridKemKey,
    ) -> Result<(Scalar, Scalar), String> {
        if recipient.public_key() != self.recipient_public {
            return Err("opening recipient key differs from enrolled key".into());
        }
        let clear = self
            .sealed
            .open(
                recipient,
                SealingPurpose::ThresholdOpeningShare,
                &share_context(context, self.party, recipient_view),
                64,
            )
            .map_err(|e| e.to_string())?;
        let value = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            clear[..32].try_into().expect("fixed size"),
        ))
        .ok_or("noncanonical opening value")?;
        let blinding = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            clear[32..].try_into().expect("fixed size"),
        ))
        .ok_or("noncanonical opening blinding")?;
        Ok((value, blinding + self.blinding_adjustment))
    }
}

pub fn opening_context(job_id: &[u8; 32], leg: &str) -> Result<[u8; 32], String> {
    if !matches!(
        leg,
        "securities_delivery" | "securities_refund" | "cash_delivery" | "cash_refund"
    ) {
        return Err("claim opening leg is invalid".into());
    }
    let mut hash = sha2::Sha256::new();
    hash.update(ENVELOPE_DOMAIN);
    hash.update(b":context:");
    hash.update(job_id);
    hash.update((leg.len() as u64).to_be_bytes());
    hash.update(leg.as_bytes());
    Ok(hash.finalize().into())
}

/// The caller obtains recipient_public from its independently enrolled recipient directory.
pub fn encrypt_opening_share<R: RngCore + CryptoRng>(
    context: [u8; 32],
    party: PartyId,
    value_share: Scalar,
    blinding_share: Scalar,
    recipient_view: &RistrettoPoint,
    recipient_public: &[u8],
    _rng: &mut R,
) -> Result<EncryptedOpeningShare, String> {
    if party == 0 || *recipient_view == RistrettoPoint::identity() {
        return Err("opening share needs a party and recipient".into());
    }
    let mut clear = zkfmi_crypto::traits::SecretBytes::new(vec![0u8; 64]);
    clear[..32].copy_from_slice(value_share.as_bytes());
    clear[32..].copy_from_slice(blinding_share.as_bytes());
    let sealed = SealedMessage::seal(
        recipient_public,
        SealingPurpose::ThresholdOpeningShare,
        &share_context(&context, party, recipient_view),
        clear.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    Ok(EncryptedOpeningShare {
        party,
        recipient_public: recipient_public.to_vec(),
        sealed,
        blinding_adjustment: Scalar::ZERO,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpeningEnvelope {
    pub context: [u8; 32],
    pub threshold: usize,
    pub recipient_view: RistrettoPoint,
    pub shares: Vec<EncryptedOpeningShare>,
}

impl OpeningEnvelope {
    pub fn new(
        context: [u8; 32],
        threshold: usize,
        recipient_view: RistrettoPoint,
        shares: Vec<EncryptedOpeningShare>,
    ) -> Result<Self, String> {
        let value = Self {
            context,
            threshold,
            recipient_view,
            shares,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.threshold == 0
            || self.shares.len() < self.threshold
            || self.shares.len() > 64
            || self.recipient_view == RistrettoPoint::identity()
        {
            return Err("opening envelope has invalid dimensions".into());
        }
        let mut parties = BTreeSet::new();
        for share in &self.shares {
            share.validate()?;
            if share.recipient_public != self.shares[0].recipient_public {
                return Err("opening shares disagree on enrolled recipient key".into());
            }
            if !parties.insert(share.party) {
                return Err("opening envelope repeats a proof party".into());
            }
        }
        Ok(())
    }

    /// Decrypt one exact threshold subset. Supplying more parties is rejected
    /// so callers cannot silently pick a convenient subset after one fails.
    pub fn decrypt(
        &self,
        recipient_view_secret: &Scalar,
        recipient_key: &HybridKemKey,
        quorum: &[PartyId],
    ) -> Result<(Scalar, Scalar), String> {
        self.validate()?;
        if G * recipient_view_secret != self.recipient_view
            || quorum.len() != self.threshold
            || quorum.iter().copied().collect::<BTreeSet<_>>().len() != quorum.len()
        {
            return Err("claim opening uses another recipient or quorum".into());
        }
        let coefficients = lagrange_at_zero(quorum)?;
        let mut value = Scalar::ZERO;
        let mut blinding = Scalar::ZERO;
        for party in quorum {
            let share = self
                .shares
                .iter()
                .find(|share| share.party == *party)
                .ok_or_else(|| "claim opening quorum names an absent proof party".to_string())?;
            let (value_share, blinding_share) =
                share.opening(&self.context, &self.recipient_view, recipient_key)?;
            let coefficient = coefficients
                .get(party)
                .ok_or_else(|| "claim opening interpolation omitted a party".to_string())?;
            value += coefficient * value_share;
            blinding += coefficient * blinding_share;
        }
        Ok((value, blinding))
    }

    pub fn decrypt_u64(
        &self,
        recipient_view_secret: &Scalar,
        recipient_key: &HybridKemKey,
        quorum: &[PartyId],
        bits: usize,
    ) -> Result<(u64, Scalar), String> {
        if bits == 0 || bits > 64 {
            return Err("claim opening amount range is outside the supported bound".into());
        }
        let (value, blinding) = self.decrypt(recipient_view_secret, recipient_key, quorum)?;
        // Scalars created from a u64 use the canonical little-endian encoding.
        // Recover that encoding directly instead of performing an O(2^bits)
        // search, which made a 32-bit settlement claim unusable in practice.
        let encoded = value.to_bytes();
        if encoded[8..].iter().any(|byte| *byte != 0) {
            return Err("claim opening is outside the u64 amount range".into());
        }
        let amount = u64::from_le_bytes(
            encoded[..8]
                .try_into()
                .expect("checked eight-byte scalar prefix"),
        );
        if bits < 64 && amount >= (1_u64 << bits) {
            return Err("claim opening is outside its declared amount range".into());
        }
        Ok((amount, blinding))
    }

    pub fn digest(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        let mut hash = sha2::Sha256::new();
        hash.update(ENVELOPE_DOMAIN);
        hash.update(self.context);
        hash.update((self.threshold as u64).to_be_bytes());
        hash.update(self.recipient_view.compress().as_bytes());
        hash.update((self.shares.len() as u64).to_be_bytes());
        for share in &self.shares {
            hash.update((share.party as u64).to_be_bytes());
            hash.update(&share.recipient_public);
            hash.update(share.sealed.binding_bytes());
            hash.update(share.blinding_adjustment.to_bytes());
        }
        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_sigma::deal;
    use rand_core::OsRng;
    use zkfmi_zk::pedersen::Pedersen;

    #[test]
    fn recipient_recovers_any_threshold_subset_but_another_key_cannot() {
        let recipient = Scalar::from(77_u64);
        let recipient_key = HybridKemKey::generate().unwrap();
        let other = Scalar::from(78_u64);
        let amount = 4_300_000_000_u64;
        let value = Scalar::from(amount);
        let blinding = Scalar::from(91_u64);
        let parties = (1..=7).collect::<Vec<_>>();
        let shares = deal(
            &Pedersen::new(b"opening-envelope-test"),
            &value,
            &blinding,
            &parties,
            2,
            &mut OsRng,
        )
        .unwrap();
        let context = opening_context(&[5_u8; 32], "cash_delivery").unwrap();
        let encrypted = parties
            .iter()
            .map(|party| {
                encrypt_opening_share(
                    context,
                    *party,
                    shares.value_shares[party],
                    shares.blinding_shares[party],
                    &(G * recipient),
                    &recipient_key.public_key(),
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect();
        let envelope = OpeningEnvelope::new(context, 3, G * recipient, encrypted).unwrap();
        for first in 1..=5 {
            for second in first + 1..=6 {
                for third in second + 1..=7 {
                    assert_eq!(
                        envelope
                            .decrypt_u64(&recipient, &recipient_key, &[first, second, third], 64)
                            .unwrap(),
                        (amount, blinding)
                    );
                }
            }
        }
        let wrong_key = HybridKemKey::generate().unwrap();
        assert!(envelope
            .decrypt(&recipient, &wrong_key, &[1, 4, 7])
            .is_err());
        for component in 0..6 {
            let mut altered = envelope.clone();
            match component {
                0 => altered.shares[0].sealed.kem_ciphertext[0] ^= 1,
                1 => altered.shares[0].sealed.kem_ciphertext[32] ^= 1,
                2 => altered.shares[0].sealed.nonce[0] ^= 1,
                3 => altered.shares[0].sealed.ciphertext[0] ^= 1,
                4 => altered.shares[0].sealed.tag[0] ^= 1,
                _ => altered.context[0] ^= 1,
            }
            assert!(altered
                .decrypt(&recipient, &recipient_key, &[1, 4, 7])
                .is_err());
        }
        assert!(envelope
            .decrypt_u64(&recipient, &recipient_key, &[1, 4, 7], 32)
            .is_err());
        assert_eq!(
            envelope
                .decrypt_u64(&recipient, &recipient_key, &[1, 4, 7], 64)
                .unwrap(),
            (amount, blinding)
        );
        assert!(envelope
            .decrypt_u64(&recipient, &recipient_key, &[1, 4, 7], 65)
            .is_err());
        assert!(envelope
            .decrypt(&other, &recipient_key, &[1, 4, 7])
            .is_err());
        assert!(envelope
            .decrypt(&recipient, &recipient_key, &[1, 4])
            .is_err());
    }
}
