// SPDX-License-Identifier: Apache-2.0

//! Seal a token to an X25519 key: ephemeral ECDH, HKDF-SHA256, AES-256-GCM.
use crate::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub const LABEL: &str = "scout-seal-v1";

/// sessionID:grantID:kind:generation, kind being "access" or "refresh".
pub fn aad(session: &str, grant: &str, kind: &str, generation: u32) -> Vec<u8> {
    format!("{session}:{grant}:{kind}:{generation}").into_bytes()
}

fn lp(out: &mut Vec<u8>, p: &[u8]) {
    out.extend_from_slice(&(p.len() as u32).to_be_bytes());
    out.extend_from_slice(p);
}

fn derive(shared: &[u8], aad: &[u8], epk: &[u8], rpk: &[u8]) -> Result<Aes256Gcm, Error> {
    // Length prefixes keep the info string unambiguous.
    let mut info = Vec::new();
    for p in [LABEL.as_bytes(), aad, epk, rpk] {
        lp(&mut info, p);
    }
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared).expand(&info, &mut k).map_err(|_| Error("hkdf".into()))?;
    Aes256Gcm::new_from_slice(&k).map_err(|_| Error("key".into()))
}

/// False for keys of small order (all-zero and the other low-order points), which yield a known shared secret.
pub fn is_contributory(public: &[u8; 32]) -> bool {
    EphemeralSecret::random_from_rng(OsRng).diffie_hellman(&PublicKey::from(*public)).was_contributory()
}

pub fn keypair() -> (StaticSecret, [u8; 32]) {
    let s = StaticSecret::random_from_rng(OsRng);
    let p = PublicKey::from(&s).to_bytes();
    (s, p)
}

/// Returns ephemeralPub(32) || nonce(12) || ciphertext.
pub fn seal(plaintext: &[u8], recipient: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let epk = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(Error("low-order recipient key".into()));
    }
    let g = derive(shared.as_bytes(), aad, &epk, recipient)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = g.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad }).map_err(|_| Error("seal".into()))?;
    let mut out = epk.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(sealed: &[u8], secret: &StaticSecret, aad: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() < 32 + 12 + 16 {
        return Err(Error("short ciphertext".into()));
    }
    let epk: [u8; 32] = sealed[..32].try_into().map_err(|_| Error("epk".into()))?;
    let shared = secret.diffie_hellman(&PublicKey::from(epk));
    if !shared.was_contributory() {
        return Err(Error("low-order ephemeral key".into()));
    }
    let rpk = PublicKey::from(secret).to_bytes();
    let g = derive(shared.as_bytes(), aad, &epk, &rpk)?;
    g.decrypt(Nonce::from_slice(&sealed[32..44]), Payload { msg: &sealed[44..], aad }).map_err(|_| Error("open failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_binding() {
        let (sk, pk) = keypair();
        let a = aad("s1", "g1", "refresh", 3);
        let ct = seal(b"secret-token", &pk, &a).unwrap();
        assert_eq!(open(&ct, &sk, &a).unwrap(), b"secret-token");
        assert_ne!(ct, seal(b"secret-token", &pk, &a).unwrap());
        for (name, bad) in [
            ("session", aad("s2", "g1", "refresh", 3)),
            ("grant", aad("s1", "g2", "refresh", 3)),
            ("kind", aad("s1", "g1", "access", 3)),
            ("generation", aad("s1", "g1", "refresh", 4)),
        ] {
            assert!(open(&ct, &sk, &bad).is_err(), "opened with wrong {name}");
        }
        let (other, _) = keypair();
        assert!(open(&ct, &other, &a).is_err());
        let mut t = ct.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(open(&t, &sk, &a).is_err());
    }
}
