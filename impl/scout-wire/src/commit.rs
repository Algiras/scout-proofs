// SPDX-License-Identifier: CC-BY-4.0

//! Keyed commitments, token digests and receipts. All use a dedicated key that
//! must differ from the provider client secret.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type H = Hmac<Sha256>;

fn mac(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m = H::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts {
        m.update(&(p.len() as u32).to_be_bytes());
        m.update(p);
    }
    m.finalize().into_bytes().to_vec()
}

/// HMAC(commitKey, domain || rootGrant || provider/client || generation || refreshToken)
pub fn commitment(key: &[u8], grant: &str, provider: &str, generation: u32, token: &str) -> Vec<u8> {
    mac(key, &[b"scout-commit-v1", grant.as_bytes(), provider.as_bytes(), &generation.to_be_bytes(), token.as_bytes()])
}

/// Recorded at sealing so teardown can tell which tokens this session received.
pub fn token_digest(key: &[u8], session: &str, token: &str) -> String {
    crate::hex(&mac(key, &[b"scout-token-digest-v1", session.as_bytes(), token.as_bytes()]))
}

pub struct ReceiptInput<'a> {
    pub session: &'a str,
    pub grant: &'a str,
    pub generation: u32,
    pub commitment: &'a [u8],
    pub enc_pub: &'a [u8],
    pub sig_pub: &'a [u8],
    pub policy: &'a str,
}

/// Authenticated receipt binding policy, commitment and runner keys.
pub fn receipt(key: &[u8], r: &ReceiptInput) -> String {
    crate::hex(&mac(
        key,
        &[
            b"scout-receipt-v1",
            r.session.as_bytes(),
            r.grant.as_bytes(),
            &r.generation.to_be_bytes(),
            r.commitment,
            r.enc_pub,
            r.sig_pub,
            r.policy.as_bytes(),
        ],
    ))
}

pub fn secret_hash(secret: &str) -> Vec<u8> {
    Sha256::digest([b"scout-session-secret-v1".as_slice(), secret.as_bytes()].concat()).to_vec()
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub fn sha256_hex(b: &[u8]) -> String {
    crate::hex(&Sha256::digest(b))
}
