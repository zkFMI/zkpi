//! Winner-only delivery of a fixed-size settlement instruction.
//! Hybrid KEM protects ciphertext confidentiality. The roster-pinned sender
//! authenticates the exact envelope with both Ed25519 and ML-DSA-65.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::symm::{Cipher, Crypter, Mode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;
use zkfmi_crypto::{
    backend::MlDsa65Verifier,
    hybrid::kem::{HybridKemEncapsulator, HybridKemKey},
    key::{KeyPurpose, KeyRecord},
    suite::{Suite, SuiteId, ML_DSA_65_SIG_BYTES, ML_KEM_768_CT_BYTES, ML_KEM_768_EK_BYTES},
    traits::{KemDecapsulator, KemEncapsulator, Signer as CryptoSigner, Verifier as _},
};

pub const DOMAIN: &[u8] = b"QOMM:WINNER:ENVELOPE:v3";
const LEGACY_DOMAIN: &[u8] = b"QOMM:WINNER:ENVELOPE:v2";
const INNER_DOMAIN: &[u8] = b"QOMM:WINNER:PAYLOAD:v3";
pub const CLEAR_BYTES: usize = 1024;
pub const VERSION: u8 = 3;
pub const KEM_SUITE: Suite = Suite::new(SuiteId::X25519MlKem768);
pub const AUTH_SUITE: Suite = Suite::new(SuiteId::MlDsa65);

#[derive(Clone, Copy)]
pub struct WinnerSenderAuth<'a> {
    pub ed25519: &'a VerifyingKey,
    pub pq_key: &'a KeyRecord,
    pub valid_at: u64,
}

/// This key is independent of the legacy pairwise MPC exchange key below.
#[derive(Clone)]
pub struct WinnerPrivateKey(Arc<HybridKemKey>);

#[derive(Clone)]
pub struct WinnerPublicKey(Vec<u8>);

impl WinnerPrivateKey {
    /// Share ownership without exporting seed bytes; used by recipient wallet adapters.
    pub fn shared_key(&self) -> Arc<HybridKemKey> {
        Arc::clone(&self.0)
    }

    pub fn generate() -> Result<Self, String> {
        HybridKemKey::generate()
            .map(|key| Self(Arc::new(key)))
            .map_err(|error| error.to_string())
    }

    /// Import a seed from the encrypted keystore; callers must erase the input.
    pub fn from_seed(seed: &[u8; 96]) -> Self {
        Self(Arc::new(HybridKemKey::from_seed(seed)))
    }

    pub fn public_key(&self) -> Result<WinnerPublicKey, String> {
        WinnerPublicKey::from_raw(&self.0.public_key())
    }
}

impl WinnerPublicKey {
    pub fn from_raw(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != 32 + ML_KEM_768_EK_BYTES || raw[..32] == [0; 32] {
            return Err("winner key must be X25519 + ML-KEM-768".into());
        }
        Ok(Self(raw.to_vec()))
    }

    pub fn raw_public_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
pub struct X25519PrivateKey(PKey<Private>);

#[derive(Clone)]
pub struct X25519PublicKey(PKey<Public>);

impl X25519PrivateKey {
    pub fn generate() -> Result<Self, String> {
        PKey::generate_x25519()
            .map(Self)
            .map_err(|error| error.to_string())
    }

    pub fn public_key(&self) -> Result<X25519PublicKey, String> {
        let raw = self.0.raw_public_key().map_err(|error| error.to_string())?;
        PKey::public_key_from_raw_bytes(&raw, Id::X25519)
            .map(X25519PublicKey)
            .map_err(|error| error.to_string())
    }

    pub fn raw_private_key(&self) -> Result<[u8; 32], String> {
        self.0
            .raw_private_key()
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "X25519 private key is not 32 bytes".to_string())
    }

    pub fn from_raw(raw: &[u8; 32]) -> Result<Self, String> {
        PKey::private_key_from_raw_bytes(raw, Id::X25519)
            .map(Self)
            .map_err(|error| error.to_string())
    }
}

impl X25519PublicKey {
    pub fn raw_public_key(&self) -> Result<[u8; 32], String> {
        self.0
            .raw_public_key()
            .map_err(|error| error.to_string())?
            .try_into()
            .map_err(|_| "X25519 public key is not 32 bytes".to_string())
    }

    pub fn from_raw(raw: &[u8; 32]) -> Result<Self, String> {
        PKey::public_key_from_raw_bytes(raw, Id::X25519)
            .map(Self)
            .map_err(|error| error.to_string())
    }
}

fn derive_key(
    shared: &[u8],
    ciphertext: &[u8],
    context_digest: &[u8; 32],
    quote_digest: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let hkdf = Hkdf::<Sha256>::new(Some(context_digest), shared);
    let mut info = Vec::with_capacity(DOMAIN.len() + ciphertext.len() + 36);
    info.extend_from_slice(DOMAIN);
    info.extend_from_slice(&KEM_SUITE.encode());
    info.extend_from_slice(ciphertext);
    info.extend_from_slice(quote_digest);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| "winner key derivation failed".to_string())?;
    Ok(key)
}

pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    clear: &[u8],
    associated: &[u8],
) -> Result<Vec<u8>, String> {
    let mut crypter = Crypter::new(Cipher::chacha20_poly1305(), Mode::Encrypt, key, Some(nonce))
        .map_err(|error| error.to_string())?;
    crypter
        .aad_update(associated)
        .map_err(|error| error.to_string())?;
    let mut output = vec![0_u8; clear.len() + Cipher::chacha20_poly1305().block_size()];
    let mut written = crypter
        .update(clear, &mut output)
        .map_err(|error| error.to_string())?;
    written += crypter
        .finalize(&mut output[written..])
        .map_err(|error| error.to_string())?;
    output.truncate(written);
    let mut tag = [0_u8; 16];
    crypter
        .get_tag(&mut tag)
        .map_err(|error| error.to_string())?;
    output.extend_from_slice(&tag);
    Ok(output)
}

pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    encrypted: &[u8],
    associated: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    if encrypted.len() < 16 {
        return Err("winner ciphertext is truncated".into());
    }
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
    let mut crypter = Crypter::new(Cipher::chacha20_poly1305(), Mode::Decrypt, key, Some(nonce))
        .map_err(|error| error.to_string())?;
    crypter
        .aad_update(associated)
        .map_err(|error| error.to_string())?;
    crypter.set_tag(tag).map_err(|error| error.to_string())?;
    let mut output = vec![0_u8; ciphertext.len() + Cipher::chacha20_poly1305().block_size()];
    let written = crypter
        .update(ciphertext, &mut output)
        .map_err(|error| error.to_string())?;
    match crypter.finalize(&mut output[written..]) {
        Ok(final_bytes) => {
            output.truncate(written + final_bytes);
            Ok(Some(output))
        }
        Err(_) => Ok(None),
    }
}

#[derive(Clone, Debug)]
pub struct WinnerEnvelope {
    pub version: u8,
    pub suite: Suite,
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub context_digest: [u8; 32],
    pub quote_digest: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub taker_public: [u8; 32],
    pub signature: Signature,
    pub pq_signature: Vec<u8>,
}

impl WinnerEnvelope {
    /// Canonical fixed-size persisted envelope. Unknown versions, suites,
    /// truncation and trailing data are rejected before decryption.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.pq_signature.len() != ML_DSA_65_SIG_BYTES {
            return Err("winner envelope requires a fixed ML-DSA-65 signature".into());
        }
        let mut bytes = self.unsigned()?;
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes.extend_from_slice(&self.pq_signature);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.starts_with(LEGACY_DOMAIN) {
            return Err("winner envelope v2 is unsupported".into());
        }
        let expected = DOMAIN.len()
            + 1
            + 4
            + 32
            + ML_KEM_768_CT_BYTES
            + 12
            + 32
            + 32
            + 32
            + CLEAR_BYTES
            + 16
            + 64
            + ML_DSA_65_SIG_BYTES;
        if bytes.len() != expected || !bytes.starts_with(DOMAIN) {
            return Err("winner envelope has an invalid encoding".into());
        }
        let mut at = DOMAIN.len();
        let version = bytes[at];
        at += 1;
        if version != VERSION || bytes[at..at + 4] != KEM_SUITE.encode() {
            return Err("unsupported winner-envelope version or KEM suite".into());
        }
        at += 4;
        let kem_ciphertext = bytes[at..at + 32 + ML_KEM_768_CT_BYTES].to_vec();
        at += 32 + ML_KEM_768_CT_BYTES;
        let nonce = bytes[at..at + 12].try_into().expect("checked fixed length");
        at += 12;
        let context_digest = bytes[at..at + 32].try_into().expect("checked fixed length");
        at += 32;
        let quote_digest = bytes[at..at + 32].try_into().expect("checked fixed length");
        at += 32;
        let taker_public = bytes[at..at + 32].try_into().expect("checked fixed length");
        at += 32;
        let ciphertext = bytes[at..at + CLEAR_BYTES + 16].to_vec();
        at += CLEAR_BYTES + 16;
        let signature =
            Signature::from_bytes(bytes[at..at + 64].try_into().expect("checked fixed length"));
        at += 64;
        let pq_signature = bytes[at..].to_vec();
        Ok(Self {
            version,
            suite: KEM_SUITE,
            kem_ciphertext,
            nonce,
            context_digest,
            quote_digest,
            ciphertext,
            taker_public,
            signature,
            pq_signature,
        })
    }

    pub fn unsigned(&self) -> Result<Vec<u8>, String> {
        if self.version != VERSION || self.suite != KEM_SUITE {
            return Err("unsupported winner-envelope version or KEM suite".into());
        }
        if self.kem_ciphertext.len() != 32 + ML_KEM_768_CT_BYTES {
            return Err("winner envelope requires both KEM components".into());
        }
        if self.ciphertext.len() != CLEAR_BYTES + 16 {
            return Err("winner ciphertext is not the fixed wire size".into());
        }
        let mut body = Vec::with_capacity(DOMAIN.len() + 141 + self.ciphertext.len());
        body.extend_from_slice(DOMAIN);
        body.push(self.version);
        body.extend_from_slice(&self.suite.encode());
        body.extend_from_slice(&self.kem_ciphertext);
        body.extend_from_slice(&self.nonce);
        body.extend_from_slice(&self.context_digest);
        body.extend_from_slice(&self.quote_digest);
        body.extend_from_slice(&self.taker_public);
        body.extend_from_slice(&self.ciphertext);
        Ok(body)
    }

    pub fn commitment(&self) -> Result<[u8; 32], String> {
        if self.pq_signature.len() != ML_DSA_65_SIG_BYTES {
            return Err("winner envelope requires a fixed ML-DSA-65 signature".into());
        }
        Ok(Sha256::new()
            .chain_update(self.unsigned()?)
            .chain_update(self.signature.to_bytes())
            .chain_update(&self.pq_signature)
            .finalize()
            .into())
    }

    pub fn verify_taker(
        &self,
        expected: &VerifyingKey,
        pq_key: &KeyRecord,
        now: u64,
    ) -> Result<(), String> {
        if expected.as_bytes() != &self.taker_public {
            return Err(
                "winner envelope signature substituted its roster-pinned Ed25519 key".into(),
            );
        }
        pq_key
            .valid_at(now)
            .map_err(|error| format!("winner envelope PQ key is unavailable: {error}"))?;
        if pq_key.suite != AUTH_SUITE || pq_key.purpose != KeyPurpose::SettlementInstruction {
            return Err("winner envelope requires the roster settlement ML-DSA-65 key".into());
        }
        let body = self.unsigned()?;
        // Evaluate both components before deciding. A valid component never
        // converts a failure of the other component into acceptance.
        let classical = expected.verify_strict(&body, &self.signature);
        let pq = MlDsa65Verifier.verify(
            KeyPurpose::SettlementInstruction,
            &pq_key.public_key,
            &body,
            &self.pq_signature,
        );
        if classical.is_err() || pq.is_err() {
            return Err("winner envelope sender signatures are invalid".into());
        }
        Ok(())
    }
}

pub fn seal_for_winner(
    maker_id: &str,
    maker_key: &WinnerPublicKey,
    payload: &[u8],
    context: &[u8],
    quote_digest: [u8; 32],
    taker_key: &SigningKey,
    taker_pq: &dyn CryptoSigner,
) -> Result<WinnerEnvelope, String> {
    if taker_pq.suite() != AUTH_SUITE {
        return Err("winner envelope signer must use ML-DSA-65".into());
    }
    let maker = maker_id.as_bytes();
    if maker.is_empty() || maker.len() > 255 {
        return Err("maker identifier must contain 1..255 UTF-8 bytes".into());
    }
    let context_digest: [u8; 32] = Sha256::digest(context).into();
    let mut fixed = Zeroizing::new(Vec::new());
    fixed.extend_from_slice(INNER_DOMAIN);
    fixed.push(maker.len() as u8);
    fixed.extend_from_slice(maker);
    fixed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    fixed.extend_from_slice(payload);
    fixed.extend_from_slice(&context_digest);
    fixed.extend_from_slice(&quote_digest);
    if fixed.len() > CLEAR_BYTES {
        return Err(format!(
            "settlement payload exceeds {CLEAR_BYTES} encrypted bytes"
        ));
    }
    fixed.resize(CLEAR_BYTES, 0);
    OsRng.fill_bytes(&mut fixed[INNER_DOMAIN.len() + 1 + maker.len() + 4 + payload.len() + 64..]);
    let encapsulation = HybridKemEncapsulator
        .encapsulate(&maker_key.0)
        .map_err(|error| error.to_string())?;
    let kem_ciphertext = encapsulation.ciphertext;
    let key = derive_key(
        &encapsulation.shared_secret,
        &kem_ciphertext,
        &context_digest,
        &quote_digest,
    )?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let associated = [
        DOMAIN,
        &KEM_SUITE.encode(),
        &kem_ciphertext,
        &context_digest,
        &quote_digest,
    ]
    .concat();
    let ciphertext = encrypt(&key, &nonce, &fixed, &associated)?;
    let taker_public = taker_key.verifying_key().to_bytes();
    let mut envelope = WinnerEnvelope {
        version: VERSION,
        suite: KEM_SUITE,
        kem_ciphertext,
        nonce,
        context_digest,
        quote_digest,
        ciphertext,
        taker_public,
        signature: Signature::from_bytes(&[0; 64]),
        pq_signature: Vec::new(),
    };
    let unsigned = envelope.unsigned()?;
    envelope.signature = taker_key.sign(&unsigned);
    envelope.pq_signature = taker_pq
        .sign(KeyPurpose::SettlementInstruction, &unsigned)
        .map_err(|error| error.to_string())?;
    if envelope.pq_signature.len() != ML_DSA_65_SIG_BYTES {
        return Err("winner envelope signer returned an invalid ML-DSA-65 signature".into());
    }
    Ok(envelope)
}

pub fn open_if_winner(
    envelope: &WinnerEnvelope,
    maker_id: &str,
    private_keys: &[WinnerPrivateKey],
    context: &[u8],
    quote_digest: [u8; 32],
    sender: WinnerSenderAuth<'_>,
) -> Result<Option<Vec<u8>>, String> {
    envelope.verify_taker(sender.ed25519, sender.pq_key, sender.valid_at)?;
    let context_digest: [u8; 32] = Sha256::digest(context).into();
    if envelope.context_digest != context_digest || envelope.quote_digest != quote_digest {
        return Err("the envelope is bound to another quote or market context".into());
    }
    let associated = [
        DOMAIN,
        &envelope.suite.encode(),
        &envelope.kem_ciphertext,
        &context_digest,
        &quote_digest,
    ]
    .concat();
    let mut clear = None;
    for private in private_keys {
        let key = derive_key(
            &private
                .0
                .decapsulate(&envelope.kem_ciphertext)
                .map_err(|error| error.to_string())?,
            &envelope.kem_ciphertext,
            &context_digest,
            &quote_digest,
        )?;
        if let Some(opened) = decrypt(&key, &envelope.nonce, &envelope.ciphertext, &associated)? {
            clear = Some(opened);
            break;
        }
    }
    let Some(clear) = clear.map(Zeroizing::new) else {
        return Ok(None);
    };
    if !clear.starts_with(INNER_DOMAIN) {
        return Err("decrypted winner payload has the wrong domain".into());
    }
    let mut at = INNER_DOMAIN.len();
    let maker_len = usize::from(clear[at]);
    at += 1;
    let recipient = std::str::from_utf8(
        clear
            .get(at..at + maker_len)
            .ok_or_else(|| "decrypted winner payload has an invalid length".to_string())?,
    )
    .map_err(|_| "decrypted winner recipient is not UTF-8")?;
    at += maker_len;
    let payload_len = u32::from_be_bytes(
        clear
            .get(at..at + 4)
            .ok_or_else(|| "decrypted winner payload has an invalid length".to_string())?
            .try_into()
            .expect("four-byte length"),
    ) as usize;
    at += 4;
    let end = at
        .checked_add(payload_len)
        .ok_or_else(|| "decrypted winner payload has an invalid length".to_string())?;
    if end + 64 > clear.len() {
        return Err("decrypted winner payload has an invalid length".into());
    }
    if recipient != maker_id {
        return Err("a key opened an envelope addressed to another maker".into());
    }
    if clear[end..end + 32] != context_digest || clear[end + 32..end + 64] != quote_digest {
        return Err("the encrypted payload and public header disagree".into());
    }
    Ok(Some(clear[at..end].to_vec()))
}
