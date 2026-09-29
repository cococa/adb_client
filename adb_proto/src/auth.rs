//! Host RSA identity used by ADB authentication.

use base64::{Engine, engine::general_purpose::STANDARD};
use num_bigint::{BigUint, ModInverse};
use num_traits::{FromPrimitive, ToPrimitive};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};

use crate::ProtoError;

const KEY_BITS: usize = 2048;
const MODULUS_SIZE_WORDS: u32 = 64;

/// A 2048-bit host key. Storage is the caller's concern: native drivers keep
/// PKCS#8 PEM on disk, the browser keeps it in IndexedDB.
#[derive(Clone, Debug)]
pub struct AdbKey {
    private_key: RsaPrivateKey,
}

fn key_error(error: impl ToString) -> ProtoError {
    ProtoError::Key(error.to_string())
}

impl AdbKey {
    /// Generates a new host key. This takes noticeable time on wasm.
    pub fn generate() -> Result<Self, ProtoError> {
        Ok(Self {
            private_key: RsaPrivateKey::new(&mut rsa::rand_core::OsRng, KEY_BITS)
                .map_err(key_error)?,
        })
    }

    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, ProtoError> {
        Ok(Self {
            private_key: RsaPrivateKey::from_pkcs8_pem(pem).map_err(key_error)?,
        })
    }

    pub fn to_pkcs8_pem(&self) -> Result<String, ProtoError> {
        Ok(self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(key_error)?
            .to_string())
    }

    /// Signs an AUTH token (SHA-1 DigestInfo, PKCS#1 v1.5), as adbd expects.
    pub fn sign_token(&self, token: &[u8]) -> Result<Vec<u8>, ProtoError> {
        self.private_key
            .sign(Pkcs1v15Sign::new::<sha1::Sha1>(), token)
            .map_err(key_error)
    }

    /// Public key in Android's `adbkey.pub` format, NUL-terminated for the
    /// AUTH(RSAPUBLICKEY) payload. `comment` is shown on the phone's prompt.
    pub fn android_public_key(&self, comment: &str) -> Result<Vec<u8>, ProtoError> {
        // Port of android_pubkey_encode() from AOSP libcrypto_utils.
        let modulus = BigUint::from_bytes_le(&self.private_key.n().to_bytes_le());
        let exponent = self
            .private_key
            .e()
            .to_u32()
            .ok_or_else(|| key_error("public exponent does not fit in u32"))?;

        let r32 = BigUint::from_u64(1 << 32).expect("2^32 fits");
        let r = BigUint::from(1u32) << KEY_BITS;
        let rr = r.modpow(&BigUint::from(2u32), &modulus);
        let n0inv = (&modulus % &r32)
            .mod_inverse(&r32)
            .and_then(|v| v.to_biguint())
            .ok_or_else(|| key_error("modulus is not invertible mod 2^32"))?;
        let n0inv = (r32 - n0inv)
            .to_u32()
            .ok_or_else(|| key_error("n0inv does not fit in u32"))?;

        // Both integers are fixed-width arrays; BigUint drops high zero bytes.
        let width = MODULUS_SIZE_WORDS as usize * 4;
        let mut modulus = modulus.to_bytes_le();
        let mut rr = rr.to_bytes_le();
        modulus.resize(width, 0);
        rr.resize(width, 0);

        let mut raw = Vec::with_capacity(12 + width * 2);
        raw.extend_from_slice(&MODULUS_SIZE_WORDS.to_le_bytes());
        raw.extend_from_slice(&n0inv.to_le_bytes());
        raw.extend_from_slice(&modulus);
        raw.extend_from_slice(&rr);
        raw.extend_from_slice(&exponent.to_le_bytes());

        let mut out = format!("{} {comment}", STANDARD.encode(raw)).into_bytes();
        out.push(0);
        Ok(out)
    }
}
