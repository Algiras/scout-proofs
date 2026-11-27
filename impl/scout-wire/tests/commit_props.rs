// SPDX-License-Identifier: Apache-2.0

mod support;

use scout_wire::commit::{commitment, ct_eq, receipt, secret_hash, sha256_hex, token_digest, ReceiptInput};
use support::Rng;

const KEY: &[u8] = b"commit-key-0123456789abcdef";

#[test]
fn labels_separate_the_domains() {
    let s = "same";
    let c = scout_wire::hex(&commitment(KEY, s, s, 0, s));
    let d = token_digest(KEY, s, s);
    let r = receipt(
        KEY,
        &ReceiptInput {
            session: s,
            grant: s,
            generation: 0,
            commitment: s.as_bytes(),
            enc_pub: s.as_bytes(),
            sig_pub: s.as_bytes(),
            policy: s,
        },
    );
    let h = scout_wire::hex(&secret_hash(s));
    let all = [c, d, r, h, sha256_hex(s.as_bytes())];
    for i in 0..all.len() {
        for j in i + 1..all.len() {
            assert_ne!(all[i], all[j], "{i} and {j}");
        }
    }
    assert_ne!(commitment(KEY, "a", "p", 0, "t"), commitment(b"commit-key-0123456789abcdeX", "a", "p", 0, "t"));
}

#[test]
fn moving_bytes_between_adjacent_fields_changes_the_mac() {
    let mut rng = Rng::new(3);
    for _ in 0..500 {
        let all: String = (0..2 + rng.below(12)).map(|_| *rng.pick(&['a', 'b', ':', '0', '\u{e9}'])).collect();
        let cuts: Vec<usize> = all.char_indices().map(|(i, _)| i).chain([all.len()]).collect();
        let (x, y) = (*rng.pick(&cuts), *rng.pick(&cuts));
        if x == y {
            continue;
        }
        let (a, b) = (x.min(y), x.max(y));
        let base = commitment(KEY, &all[..a], &all[a..], 1, "tok");
        let moved = commitment(KEY, &all[..b], &all[b..], 1, "tok");
        assert_ne!(base, moved, "cut {a} vs {b} of {all:?}");
        let t1 = token_digest(KEY, &all[..a], &all[a..]);
        let t2 = token_digest(KEY, &all[..b], &all[b..]);
        assert_ne!(t1, t2);
    }
    assert_ne!(commitment(KEY, "ab", "c", 0, "t"), commitment(KEY, "a", "bc", 0, "t"));
    assert_ne!(commitment(KEY, "g", "p", 0, "1"), commitment(KEY, "g", "p", 1, "1"));
    assert_ne!(commitment(KEY, "g", "p", 1, "t"), commitment(KEY, "g", "p", 256, "t"));
    let base = ReceiptInput { session: "s", grant: "g", generation: 1, commitment: b"cc", enc_pub: b"ee", sig_pub: b"ss", policy: "p" };
    let r0 = receipt(KEY, &base);
    for v in [
        ReceiptInput { session: "sg", grant: "", ..base },
        ReceiptInput { commitment: b"c", enc_pub: b"cee", ..base },
        ReceiptInput { enc_pub: b"e", sig_pub: b"ess", ..base },
        ReceiptInput { sig_pub: b"s", policy: "sp", ..base },
        ReceiptInput { generation: 2, ..base },
    ] {
        assert_ne!(receipt(KEY, &v), r0);
    }
}

#[test]
fn ct_eq_is_exact() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"abcd"));
    assert!(!ct_eq(b"", b"a"));
    assert!(ct_eq(b"", b""));
}
