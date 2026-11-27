// SPDX-License-Identifier: Apache-2.0

//! Canonical JSON and signed proofs over generated values.
mod support;

use ed25519_dalek::SigningKey;
use scout_wire::proof::{canonical, sign, Envelope, WINDOW};
use scout_wire::{b64, random_bytes};
use serde_json::{json, Map, Value};
use support::Rng;

fn key() -> SigningKey {
    SigningKey::from_bytes(&random_bytes::<32>())
}

fn gen_value(rng: &mut Rng, depth: usize) -> Value {
    match rng.below(if depth == 0 { 6 } else { 8 }) {
        0 => Value::Null,
        1 => json!(rng.below(2) == 0),
        2 => {
            let r = rng.next();
            json!(*rng.pick(&[0u64, 1, u64::MAX, i64::MAX as u64, i64::MAX as u64 + 1, r]))
        }
        3 => {
            let r = rng.next() as i64;
            json!(*rng.pick(&[0i64, -1, i64::MIN, i64::MAX, r]))
        }
        4 => json!(*rng.pick(&["", "a", "z", "\u{e9}", "\u{4e2d}\u{6587}", "\u{1f600}", "a\"b\\c", "\n\t\u{0}", "\u{2028}"])),
        5 => json!(rng.below(1000) as f64 / 8.0),
        6 => Value::Array((0..rng.below(4)).map(|_| gen_value(rng, depth - 1)).collect()),
        _ => Value::Object(gen_object(rng, depth - 1)),
    }
}

fn gen_object(rng: &mut Rng, depth: usize) -> Map<String, Value> {
    let mut m = Map::new();
    for _ in 0..rng.below(6) {
        let k = format!("{}{}", rng.pick(&["k", "\u{e9}", "A", "zz", ""]), rng.below(20));
        m.insert(k, gen_value(rng, depth));
    }
    m
}

fn shuffled_text(rng: &mut Rng, v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut items: Vec<(&String, &Value)> = m.iter().collect();
            for i in (1..items.len()).rev() {
                items.swap(i, rng.below(i + 1));
            }
            let parts: Vec<String> =
                items.into_iter().map(|(k, v)| format!("{} : {}", serde_json::to_string(k).unwrap(), shuffled_text(rng, v))).collect();
            format!("{{ {} }}", parts.join(" , "))
        }
        Value::Array(a) => format!("[ {} ]", a.iter().map(|x| shuffled_text(rng, x)).collect::<Vec<_>>().join(" , ")),
        other => other.to_string(),
    }
}

#[test]
fn canonical_is_independent_of_input_key_order_and_whitespace() {
    let mut rng = Rng::new(11);
    for _ in 0..3000 {
        let v = gen_value(&mut rng, 3);
        let text = shuffled_text(&mut rng, &v);
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(canonical(&parsed), canonical(&v), "{text}");
        let again: Value = serde_json::from_slice(&canonical(&v)).unwrap();
        assert_eq!(canonical(&again), canonical(&v));
    }
}

#[test]
fn canonical_keys_are_sorted_and_number_edges_are_exact() {
    let v: Value = serde_json::from_str(r#"{"b":1,"a":2,"a":3}"#).unwrap();
    assert_eq!(canonical(&v), br#"{"a":3,"b":1}"#, "duplicate keys: the last one wins");
    let e = json!({ "u": u64::MAX, "i": i64::MIN, "j": i64::MAX, "z": 0 });
    assert_eq!(canonical(&e), br#"{"i":-9223372036854775808,"j":9223372036854775807,"u":18446744073709551615,"z":0}"#);
    let back: Value = serde_json::from_slice(&canonical(&e)).unwrap();
    assert_eq!(back["u"].as_u64(), Some(u64::MAX));
    assert_eq!(back["i"].as_i64(), Some(i64::MIN));
    assert_ne!(canonical(&json!({"a": 1})), canonical(&json!({"a": 1.0})));
}

fn request(rng: &mut Rng, session: &str, at: u64) -> Value {
    json!({ "method": "POST", "route": format!("/v1/sessions/{session}/renew"), "authority": "broker:8080", "session": session,
            "signedAt": at, "nonce": format!("{:x}", rng.next()), "capability": "default", "generation": rng.below(100),
            "operationId": format!("op-{}", rng.below(1000)) })
}

fn mutate_value(rng: &mut Rng, v: &Value) -> Value {
    match v {
        Value::String(s) => match rng.below(3) {
            0 => json!(format!("{s}x")),
            1 => json!(s.chars().skip(1).collect::<String>()),
            _ => json!(s.to_uppercase() + "!"),
        },
        Value::Number(n) => json!(n.as_u64().unwrap_or(0).wrapping_add(1 + rng.below(3) as u64)),
        _ => json!("changed"),
    }
}

#[test]
fn any_single_field_change_breaks_the_proof() {
    let mut rng = Rng::new(21);
    let k = key();
    let pubk = k.verifying_key().to_bytes();
    let now = 1_000_000;
    let mut checked = 0;
    for _ in 0..300 {
        let session = format!("{:032x}", rng.next());
        let env = sign(&k, request(&mut rng, &session, now));
        env.verify(&pubk, now).unwrap();
        let obj = env.body.as_object().unwrap().clone();
        for field in obj.keys() {
            let mut t = env.clone();
            t.body[field] = mutate_value(&mut rng, &obj[field]);
            assert!(t.verify(&pubk, now).is_err(), "changing {field} still verifies");
            let mut r = env.clone();
            r.body.as_object_mut().unwrap().remove(field);
            assert!(r.verify(&pubk, now).is_err(), "removing {field} still verifies");
            checked += 2;
        }
        let mut extra = env.clone();
        extra.body["extra"] = json!(1);
        assert!(extra.verify(&pubk, now).is_err());
    }
    println!("single-field mutations checked: {checked}");
}

#[test]
fn timestamp_window_edges_on_both_sides() {
    let k = key();
    let pubk = k.verifying_key().to_bytes();
    let t = 5_000_000u64;
    for (at, ok) in
        [(t, true), (t - WINDOW, true), (t + WINDOW, true), (t - WINDOW - 1, false), (t + WINDOW + 1, false), (0, false), (u64::MAX, false)]
    {
        let e = sign(&k, json!({ "signedAt": at, "session": "s" }));
        assert_eq!(e.verify(&pubk, t).is_ok(), ok, "signedAt {at} against now {t}");
    }
    let tiny = sign(&k, json!({ "signedAt": 0 }));
    assert!(tiny.verify(&pubk, WINDOW).is_ok());
    assert!(tiny.verify(&pubk, WINDOW + 1).is_err());
    assert!(sign(&k, json!({ "session": "s" })).verify(&pubk, t).is_err(), "missing signedAt");
    assert!(sign(&k, json!({ "signedAt": "5000000" })).verify(&pubk, t).is_err(), "string signedAt");
    assert!(sign(&k, json!({ "signedAt": -5 })).verify(&pubk, t).is_err(), "negative signedAt");
    assert!(sign(&k, json!({ "signedAt": 5_000_000.5 })).verify(&pubk, t).is_err(), "fractional signedAt");
}

const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0x10,
];

fn add_l(s: &mut [u8]) {
    let mut carry = 0u16;
    for (a, b) in s.iter_mut().zip(L) {
        let v = *a as u16 + b as u16 + carry;
        *a = v as u8;
        carry = v >> 8;
    }
}

#[test]
fn signature_malleability_and_malformed_signatures() {
    let mut rng = Rng::new(31);
    let k = key();
    let pubk = k.verifying_key().to_bytes();
    let env = sign(&k, json!({ "signedAt": 100, "session": "s" }));
    let raw = scout_wire::unb64(&env.sig).unwrap();
    let with = |sig: &[u8]| Envelope { body: env.body.clone(), sig: b64(sig) };
    assert!(with(&raw).verify(&pubk, 100).is_ok());
    let mut mal = raw.clone();
    add_l(&mut mal[32..]);
    assert!(with(&mal).verify(&pubk, 100).is_err(), "S + L must not verify");
    for bit in 0..512 {
        let mut f = raw.clone();
        f[bit / 8] ^= 1 << (bit % 8);
        assert!(with(&f).verify(&pubk, 100).is_err(), "flipped bit {bit}");
    }
    for len in [0, 1, 32, 63, 65, 128] {
        let sig = rng.bytes(len);
        assert!(with(&sig).verify(&pubk, 100).is_err());
        let mut cut = raw.clone();
        cut.resize(len, 0);
        assert!(with(&cut).verify(&pubk, 100).is_err());
    }
    for s in ["", "!!!!", "AAAA", &format!("{}=", env.sig), &env.sig.replace('A', "+")] {
        let e = Envelope { body: env.body.clone(), sig: s.to_string() };
        assert!(e.verify(&pubk, 100).is_err(), "{s}");
    }
    assert!(env.verify(&key().verifying_key().to_bytes(), 100).is_err());
    for len in [0usize, 31, 33, 64] {
        assert!(env.verify(&vec![7u8; len], 100).is_err());
    }
}

#[test]
fn small_order_public_keys_cannot_sign_for_everyone() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut sig = identity.to_vec();
    sig.extend_from_slice(&[0u8; 32]);
    for body in [json!({ "signedAt": 100, "session": "a" }), json!({ "signedAt": 100, "session": "b", "x": 1 })] {
        let forged = Envelope { body, sig: b64(&sig) };
        assert!(forged.verify(&identity, 100).is_err(), "identity key with a zero signature verified an arbitrary body");
    }
}

#[test]
fn envelope_survives_re_encoding_with_the_same_digest() {
    let mut rng = Rng::new(41);
    let k = key();
    let pubk = k.verifying_key().to_bytes();
    for _ in 0..200 {
        let e = sign(&k, request(&mut rng, "s1", 100));
        let text = format!("{{ \"sig\" : \"{}\" , \"body\" : {} }}", e.sig, shuffled_text(&mut rng, &e.body));
        let back: Envelope = serde_json::from_str(&text).unwrap();
        back.verify(&pubk, 100).unwrap();
        assert_eq!(back.digest(), e.digest());
    }
}
