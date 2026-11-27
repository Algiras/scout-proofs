// SPDX-License-Identifier: Apache-2.0

mod support;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use scout_wire::seal::{aad, keypair, open, seal};
use sha2::Sha256;
use support::Rng;

#[test]
fn every_single_bit_flip_fails_to_open() {
    let (sk, pk) = keypair();
    let a = aad("s1", "g1", "access", 7);
    for len in [0usize, 1, 16, 77] {
        let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
        let ct = seal(&pt, &pk, &a).unwrap();
        assert_eq!(ct.len(), 32 + 12 + len + 16);
        assert_eq!(open(&ct, &sk, &a).unwrap(), pt);
        for bit in 0..ct.len() * 8 {
            let mut t = ct.clone();
            t[bit / 8] ^= 1 << (bit % 8);
            assert!(open(&t, &sk, &a).is_err(), "bit {bit} of a {len}-byte plaintext sealed blob");
        }
    }
}

#[test]
fn truncated_extended_and_foreign_blobs_fail() {
    let mut rng = Rng::new(5);
    let (sk, pk) = keypair();
    let a = aad("s", "g", "refresh", 1);
    let ct = seal(b"token-value", &pk, &a).unwrap();
    for n in 0..ct.len() {
        assert!(open(&ct[..n], &sk, &a).is_err(), "truncated to {n}");
    }
    for extra in [1usize, 16, 100] {
        let mut t = ct.clone();
        t.extend(rng.bytes(extra));
        assert!(open(&t, &sk, &a).is_err());
    }
    let (other, _) = keypair();
    assert!(open(&ct, &other, &a).is_err(), "wrong recipient");
    for _ in 0..500 {
        let junk = rng.bytes_in(0, 200);
        assert!(open(&junk, &sk, &a).is_err());
    }
    assert!(open(&ct, &sk, b"").is_err());
}

#[test]
fn every_aad_component_is_bound() {
    let (sk, pk) = keypair();
    let ct = seal(b"t", &pk, &aad("sess", "grant", "access", 2)).unwrap();
    for bad in [
        aad("sesS", "grant", "access", 2),
        aad("sess", "grans", "access", 2),
        aad("sess", "grant", "refresh", 2),
        aad("sess", "grant", "access", 3),
        aad("sess", "grant", "access", 0),
        aad("sess", "grant", "access", u32::MAX),
        aad("", "", "", 0),
    ] {
        assert!(open(&ct, &sk, &bad).is_err());
    }
}

#[test]
fn seals_of_the_same_plaintext_differ_and_do_not_leak_it() {
    let (_, pk) = keypair();
    let a = aad("s", "g", "access", 0);
    let pt = b"plaintext-token-0123456789";
    let all: Vec<Vec<u8>> = (0..50).map(|_| seal(pt, &pk, &a).unwrap()).collect();
    for i in 0..all.len() {
        assert!(!all[i].windows(pt.len()).any(|w| w == pt));
        for j in i + 1..all.len() {
            assert_ne!(all[i], all[j]);
            assert_ne!(all[i][..32], all[j][..32], "ephemeral keys repeat");
            assert_ne!(all[i][32..44], all[j][32..44], "nonces repeat");
        }
    }
}

const LOW_ORDER: [[u8; 32]; 5] = [
    [0; 32],
    {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    },
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
        0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
        0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
    ],
    {
        let mut b = [0xffu8; 32];
        b[0] = 0xec;
        b[31] = 0x7f;
        b
    },
];

#[test]
fn low_order_recipient_keys_are_refused() {
    for (i, k) in LOW_ORDER.iter().enumerate() {
        assert!(seal(b"secret", k, &aad("s", "g", "access", 0)).is_err(), "low-order key {i} accepted");
    }
}

/// A sender can build a blob on a low-order ephemeral key whose shared secret is all zero, which it knows
/// without any secret of the recipient. `open` must not accept it.
#[test]
fn opening_a_blob_built_on_a_low_order_ephemeral_key_is_refused() {
    let (sk, pk) = keypair();
    let a = aad("s", "g", "access", 0);
    let epk = LOW_ORDER[0];
    let mut info = vec![];
    for p in [scout_wire::seal::LABEL.as_bytes(), a.as_slice(), epk.as_slice(), pk.as_slice()] {
        info.extend_from_slice(&(p.len() as u32).to_be_bytes());
        info.extend_from_slice(p);
    }
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, &[0u8; 32]).expand(&info, &mut k).unwrap();
    let nonce = [3u8; 12];
    let ct = Aes256Gcm::new_from_slice(&k).unwrap().encrypt(Nonce::from_slice(&nonce), Payload { msg: b"forged", aad: &a }).unwrap();
    let blob = [epk.as_slice(), &nonce, &ct].concat();
    assert!(open(&blob, &sk, &a).is_err(), "a blob sealed with a publicly known key was accepted");
}
