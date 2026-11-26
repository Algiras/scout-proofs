// SPDX-License-Identifier: CC-BY-4.0

//! Ed25519 proofs over canonical JSON.
use crate::{b64, unb64, Error};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const WINDOW: u64 = 300;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Envelope {
    pub body: Value,
    pub sig: String,
}

/// serde_json keeps object keys sorted (no preserve_order feature), so the
/// minimal encoding of a Value is canonical; bodies carry integers only.
pub fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

pub fn sign(key: &SigningKey, body: Value) -> Envelope {
    let sig = b64(&key.sign(&canonical(&body)).to_bytes());
    Envelope { body, sig }
}

impl Envelope {
    pub fn verify(&self, pub_key: &[u8], now: u64) -> Result<(), Error> {
        let pk: [u8; 32] = pub_key.try_into().map_err(|_| Error("bad public key".into()))?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| Error("bad public key".into()))?;
        let sig: [u8; 64] = unb64(&self.sig)?.try_into().map_err(|_| Error("bad signature".into()))?;
        vk.verify(&canonical(&self.body), &Signature::from_bytes(&sig)).map_err(|_| Error("bad signature".into()))?;
        let at = self.u64("signedAt").ok_or_else(|| Error("no signedAt".into()))?;
        if now.abs_diff(at) > WINDOW {
            return Err(Error("outside window".into()));
        }
        Ok(())
    }

    /// Identifies the exact signed request.
    pub fn digest(&self) -> Vec<u8> {
        Sha256::digest(canonical(&self.body)).to_vec()
    }

    pub fn str(&self, k: &str) -> &str {
        self.body.get(k).and_then(Value::as_str).unwrap_or("")
    }

    pub fn u64(&self, k: &str) -> Option<u64> {
        self.body.get(k).and_then(Value::as_u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&crate::random_bytes::<32>())
    }

    #[test]
    fn canonical_sorts_keys() {
        let v = json!({"b": 1, "a": {"z": 1, "y": [{"q": 1, "p": 2}]}});
        assert_eq!(canonical(&v), br#"{"a":{"y":[{"p":2,"q":1}],"z":1},"b":1}"#);
    }

    #[test]
    fn sign_verify() {
        let k = key();
        let pubk = k.verifying_key().to_bytes();
        let e = sign(&k, json!({"session": "s", "signedAt": 1000, "nonce": "n"}));
        let wire: Envelope = serde_json::from_slice(&serde_json::to_vec(&e).unwrap()).unwrap();
        wire.verify(&pubk, 1000).unwrap();
        assert!(wire.verify(&pubk, 1000 + 301).is_err());
        assert!(wire.verify(&pubk, 1000 - 301).is_err());
        assert_eq!(e.digest(), wire.digest());
        let mut t = wire.clone();
        t.body["session"] = json!("other");
        assert!(t.verify(&pubk, 1000).is_err());
        assert!(wire.verify(&key().verifying_key().to_bytes(), 1000).is_err());
    }
}
