// SPDX-License-Identifier: Apache-2.0

//! Adversarial tests of the broker: forged and replayed requests, races, crashes, bad store files, limits.
mod support;

use scout_broker::renewal::{BeginOut, BeginReq, RenewErr};
use scout_broker::store::{MemStore, Store};
use scout_core::Reject;
use scout_runner::{CallErr, Client, Grant};
use scout_wire::http::{Transport, Ureq};
use scout_wire::{b64, now_secs, Error};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use support::*;

const OPS: [&str; 4] = ["status", "grant", "renew", "revoke"];

fn url(c: &Client, op: &str) -> String {
    format!("{}{}", c.base, c.route(op))
}

/// Body for one signed endpoint, with the proof built by `signer` for `route` and extra signed fields.
fn body_for(signer: &Client, route: &str, op: &str, g: &Grant, extra: Value) -> Value {
    let mut fields = extra;
    match op {
        "renew" => {
            fields["capability"] = json!("default");
            fields["generation"] = json!(g.generation);
            fields["receipt"] = json!(g.receipt);
            fields["refreshHash"] = json!(scout_wire::commit::sha256_hex(g.refresh.as_bytes()));
            fields["operationId"] = json!("op-forged");
        }
        "revoke" => fields["tokenHashes"] = json!([scout_wire::commit::sha256_hex(g.access.as_bytes())]),
        _ => {}
    }
    let proof = signer.proof(route, fields);
    match op {
        "renew" => json!({ "proof": proof, "refreshToken": g.refresh }),
        "revoke" => json!({ "proof": proof, "tokens": [{ "kind": "access", "token": g.access }] }),
        _ => json!({ "proof": proof }),
    }
}

fn assert_refused(label: &str, (s, v): (u16, Value)) {
    assert!(s >= 400, "{label}: expected a refusal, got {s} {v}");
    assert!(s < 500, "{label}: server error {s} {v}");
}

#[test]
fn signed_endpoints_refuse_forged_captured_and_stale_proofs() {
    let st = Stack::new();
    let (mut a, ga) = st.onboard();
    let (mut b, gb) = st.onboard();
    let mut refused = 0;
    for op in OPS {
        let target = url(&a, op);
        let route = a.route(op);
        refused += 1;
        for (label, body) in [("no proof", json!({})), ("null proof", json!({ "proof": null })), ("string proof", json!({ "proof": "x" }))]
        {
            assert_refused(&format!("{op} {label}"), post(&target, &body));
            refused += 1;
        }
        // B's own valid proof for B's route, sent to A's route.
        let bs = body_for(&b, &b.route(op), op, &gb, json!({}));
        assert_refused(&format!("{op} proof of another session"), post(&target, &bs));
        // B's key signing a proof that names A's session and route.
        let (bsess, bsecret) = (b.session.clone(), b.secret.clone());
        b.session = a.session.clone();
        let forged = body_for(&b, &route, op, &ga, json!({}));
        b.session = bsess;
        b.secret = bsecret;
        assert_refused(&format!("{op} wrong key"), post(&target, &forged));
        refused += 2;
        // A's own proof with the wrong method, wrong authority, wrong session.
        for (label, extra) in [
            ("method", json!({ "method": "GET" })),
            ("authority", json!({ "authority": "evil.example" })),
            ("session", json!({ "session": b.session })),
        ] {
            assert_refused(&format!("{op} {label}"), post(&target, &body_for(&a, &route, op, &ga, extra)));
            refused += 1;
        }
        for delta in [301i64, 3600, -301, -3600] {
            let at = (now_secs() as i64 + delta) as u64;
            assert_refused(&format!("{op} signedAt {delta}"), post(&target, &body_for(&a, &route, op, &ga, json!({ "signedAt": at }))));
            refused += 1;
        }
        // Captured proof for one route replayed at every other route.
        let captured = body_for(&a, &route, op, &ga, json!({}));
        for other in OPS.iter().filter(|o| **o != op) {
            assert_refused(&format!("{op} proof replayed at {other}"), post(&url(&a, other), &captured));
            refused += 1;
        }
        // Original signature over a changed body.
        let proof = captured["proof"].as_object().unwrap().clone();
        for field in proof["body"].as_object().unwrap().keys() {
            let mut t = captured.clone();
            t["proof"]["body"][field] = json!("tampered");
            assert_refused(&format!("{op} tampered {field}"), post(&target, &t));
            refused += 1;
        }
    }
    let mut t = body_for(&a, &a.route("renew"), "renew", &ga, json!({}));
    t["refreshToken"] = json!(gb.refresh);
    assert_refused("renew with another token under the original signature", post(&url(&a, "renew"), &t));
    let mut t = body_for(&a, &a.route("revoke"), "revoke", &ga, json!({}));
    t["tokens"] = json!([{ "kind": "access", "token": gb.access }]);
    assert_refused("revoke with swapped tokens", post(&url(&a, "revoke"), &t));
    println!("forged requests refused: {}", refused + 2);
    assert_eq!(st.family_calls(), vec![0, 0]);
    assert_eq!(st.revocations(), 0);
    assert_eq!(st.whoami(&ga.access), 200);
    assert_eq!(st.whoami(&gb.access), 200);
    assert_eq!(a.status().unwrap().state, "ACTIVE");
    assert_eq!(a.renew(&ga, "op-real").unwrap().generation, 1);
    a.base = st.url();
}

#[test]
fn timestamps_just_inside_the_window_are_accepted() {
    let st = Stack::new();
    let (c, _) = st.onboard();
    for delta in [-290i64, -1, 0, 1, 290] {
        let at = (now_secs() as i64 + delta) as u64;
        let route = c.route("status");
        let (s, v) = post(&url(&c, "status"), &json!({ "proof": c.proof(&route, json!({ "signedAt": at })) }));
        assert_eq!(s, 200, "signedAt {delta}: {v}");
    }
}

#[test]
fn secret_gated_endpoints_and_key_validation() {
    let st = Stack::new();
    let mut req = Client::with_ureq(&st.url());
    req.create_unbound(3600).unwrap();
    let (other, _) = st.onboard();
    let bind = format!("{}/v1/sessions/{}/bind", st.url(), req.session);
    let (enc, sig) = (b64(&req.enc_pub), b64(&req.sig_pub()));
    for secret in [json!("wrong"), json!(""), json!(null), json!(other.secret), json!(17)] {
        assert_refused("bind", post(&bind, &json!({ "secret": secret, "encPub": enc, "sigPub": sig })));
    }
    assert_refused("bind without secret", post(&bind, &json!({ "encPub": enc, "sigPub": sig })));
    let (s, _) = (Ureq { redirects: 0 }).call("GET", &req.consent_url("alice"), &[], &[]).unwrap();
    assert_eq!(s, 409, "keys must not be pinned by a bind that failed");
    let low = b64(&[0u8; 32]);
    let mut identity = [0u8; 32];
    identity[0] = 1;
    for (e, g, label) in [
        (low.clone(), sig.clone(), "low-order encPub"),
        (enc.clone(), b64(&identity), "weak sigPub"),
        (enc.clone(), low.clone(), "zero sigPub"),
    ] {
        let (s, v) = post(&bind, &json!({ "secret": req.secret, "encPub": e, "sigPub": g }));
        assert_eq!((s, v["error"].as_str()), (400, Some("bad_key")), "bind {label}");
        let (s, v) = post(&format!("{}/v1/sessions", st.url()), &json!({ "encPub": e, "sigPub": g }));
        assert_eq!((s, v["error"].as_str()), (400, Some("bad_key")), "create {label}");
    }
    assert_eq!(post(&bind, &json!({ "secret": req.secret, "encPub": enc, "sigPub": sig })).0, 200);
    let fin = |id: &str, secret: Value| post(&format!("{}/v1/sessions/{id}/finalize", st.url()), &json!({ "secret": secret }));
    for secret in [json!("wrong"), json!(null), json!(other.secret), json!("")] {
        assert_refused("finalize", fin(&req.session, secret));
    }
    assert_eq!(fin("no-such-session", json!("x")).0, 404);
    assert_eq!(fin(&req.session, json!(req.secret)).0, 200);
}

#[test]
fn nonce_reuse_is_not_tracked_and_replays_are_bounded_by_the_protocol() {
    let st = Stack::new();
    let tr = Arc::new(Capture::default());
    let (c, g0) = st.onboard_with(tr.clone());
    let status = c.route("status");
    let body = json!({ "proof": c.proof(&status, json!({})) });
    for _ in 0..3 {
        assert_eq!(post(&url(&c, "status"), &body).0, 200, "an identical proof is accepted again: nonces are not tracked");
    }
    let renew = |g: &Grant, op: &str| {
        let r = c.renew_raw(g, op);
        (r.clone(), tr.last("renew"))
    };
    let (first, sent) = renew(&g0, "op-1");
    let first = first.unwrap();
    for _ in 0..2 {
        assert_eq!(post_bytes(&url(&c, "renew"), &sent).unwrap(), (200, first.clone()), "a captured renew request replays the same reply");
    }
    let v: Value = serde_json::from_slice(&first).unwrap();
    let g1 = c.open_grant(&v, Some(&g0.refresh)).unwrap();
    c.renew(&g1, "op-2").unwrap();
    let (s, _) = post_bytes(&url(&c, "renew"), &sent).unwrap();
    assert!(s >= 400, "the captured request must not work once the next generation was admitted");
    assert_eq!(st.family_calls(), vec![2]);
}

#[derive(Default)]
struct Capture {
    sent: Mutex<Vec<(String, Vec<u8>)>>,
}

impl Capture {
    fn last(&self, op: &str) -> Vec<u8> {
        self.sent.lock().unwrap().iter().rev().find(|(u, _)| u.ends_with(op)).map(|x| x.1.clone()).unwrap()
    }
}

impl Transport for Capture {
    fn call(&self, m: &str, u: &str, h: &[(&str, &str)], b: &[u8]) -> Result<(u16, Vec<u8>), Error> {
        self.sent.lock().unwrap().push((u.to_string(), b.to_vec()));
        (Ureq { redirects: 0 }).call(m, u, h, b)
    }
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

fn junk(r: &mut Lcg, depth: u32) -> Value {
    match r.next() % if depth == 0 { 6 } else { 8 } {
        0 => Value::Null,
        1 => json!(r.next().is_multiple_of(2)),
        2 => json!(r.next()),
        3 => json!(-(r.next() as i64)),
        4 => json!(["", "x", "\u{0}", "../../etc", "a.b.c", "0".repeat(70).as_str()][(r.next() % 6) as usize]),
        5 => json!(f64::from(r.next() as u32) / 7.0),
        6 => Value::Array((0..r.next() % 3).map(|_| junk(r, depth - 1)).collect()),
        _ => {
            let mut m = serde_json::Map::new();
            for k in [
                "proof",
                "body",
                "sig",
                "secret",
                "encPub",
                "sigPub",
                "tokens",
                "refreshToken",
                "kind",
                "token",
                "ttlSeconds",
                "capability",
                "method",
            ] {
                if r.next().is_multiple_of(3) {
                    m.insert(k.to_string(), junk(r, depth - 1));
                }
            }
            Value::Object(m)
        }
    }
}

#[test]
fn json_fuzz_on_every_endpoint_never_crashes_the_broker() {
    let st = Stack::new();
    let (c, g) = st.onboard();
    let mut r = Lcg(99);
    let mut sent = 0;
    let routes: Vec<String> = ["/v1/sessions".to_string()]
        .into_iter()
        .chain(
            ["bind", "grant", "renew", "revoke", "finalize", "status", "consent"]
                .iter()
                .flat_map(|op| [format!("/v1/sessions/{}/{op}", c.session), format!("/v1/sessions/nope/{op}")]),
        )
        .collect();
    for i in 0..4000 {
        let route = &routes[i % routes.len()];
        let body = if i % 5 == 0 { (0..r.next() % 80).map(|_| r.next() as u8).collect() } else { j(&junk(&mut r, 3)) };
        let (s, _) = post_bytes(&format!("{}{route}", st.url()), &body)
            .unwrap_or_else(|e| panic!("no answer to {route} with {:?}: {e}", String::from_utf8_lossy(&body)));
        assert!(s < 500, "{route} answered {s} to {:?}", String::from_utf8_lossy(&body));
        sent += 1;
    }
    println!("fuzzed broker requests: {sent}");
    assert_eq!(c.status().unwrap().state, "ACTIVE", "fuzzing must not have changed the legitimate session");
    assert_eq!(c.renew(&g, "op-after-fuzz").unwrap().generation, 1);
    st.onboard();
}

#[test]
fn concurrent_renewals_admit_one_operation_per_generation() {
    let st = Stack::new();
    let (c, mut g) = st.onboard();
    for gen in 0..5u32 {
        let (cr, gr) = (&c, &g);
        let results: Vec<_> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..32).map(|t| s.spawn(move || cr.renew_raw(gr, &format!("op-{gen}-{t}")))).collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let ok: Vec<&Vec<u8>> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(ok.len(), 1, "generation {gen}: {} operations were admitted", ok.len());
        for r in results.iter().filter(|r| r.is_err()) {
            assert!(matches!(r, Err(CallErr::Api(400..=499, _))), "{r:?}");
        }
        let v: Value = serde_json::from_slice(ok[0]).unwrap();
        g = c.open_grant(&v, Some(&g.refresh)).unwrap();
        assert_eq!(g.generation, gen + 1);
        assert_eq!(st.family_calls(), vec![u64::from(gen) + 1], "provider refreshes equal committed generations");
    }
    assert_eq!(st.whoami(&g.access), 200);
}

#[test]
fn concurrent_begin_reserves_exactly_once() {
    let st = Stack::new();
    let (c, g) = st.onboard();
    let outs: Vec<_> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..32)
            .map(|t| {
                let (st, c, g) = (&st, &c, &g);
                s.spawn(move || {
                    let op = format!("op-{t}");
                    st.broker().renewer.begin(&BeginReq { session: &c.session, op: &op, gen: 0, receipt: &g.receipt, token: &g.refresh })
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(outs.iter().filter(|o| matches!(o, Ok(BeginOut::Reserved(_)))).count(), 1);
    assert!(
        outs.iter().all(|o| matches!(o, Ok(BeginOut::Reserved(_)) | Err(RenewErr::Reject(Reject::Competing | Reject::InProgress)))),
        "{outs:?}"
    );
    assert_eq!(st.family_calls(), vec![0]);
}

#[test]
fn concurrent_grant_fetches_release_one_sealed_response() {
    let st = Stack::new();
    let mut c = Client::with_ureq(&st.url());
    c.create(3600).unwrap();
    (Ureq { redirects: 5 }).call("GET", &c.consent_url("alice"), &[], &[]).unwrap();
    let route = c.route("grant");
    let distinct: Vec<(u16, Vec<u8>)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..32)
            .map(|_| {
                let body = j(&json!({ "proof": c.proof(&route, json!({})) }));
                let target = url(&c, "grant");
                s.spawn(move || post_bytes(&target, &body).unwrap())
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let released: Vec<&(u16, Vec<u8>)> = distinct.iter().filter(|r| r.0 == 200).collect();
    assert_eq!(released.len(), 1, "different requests: exactly one gets the sealed grant");
    assert!(distinct.iter().filter(|r| r.0 != 200).all(|r| r.0 == 409));

    let mut c2 = Client::with_ureq(&st.url());
    c2.create(3600).unwrap();
    (Ureq { redirects: 5 }).call("GET", &c2.consent_url("alice"), &[], &[]).unwrap();
    let route = c2.route("grant");
    let body = j(&json!({ "proof": c2.proof(&route, json!({})) }));
    let target = url(&c2, "grant");
    let same: Vec<(u16, Vec<u8>)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..32).map(|_| s.spawn(|| post_bytes(&target, &body).unwrap())).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(same.iter().all(|r| r.0 == 200));
    assert!(same.iter().all(|r| r.1 == same[0].1), "an identical request always gets the same bytes");
}

#[test]
fn closing_while_renewing_releases_and_commits_nothing_afterwards() {
    for round in 0..15 {
        let st = Stack::new();
        let (c, g) = st.onboard();
        let (cr, gr) = (&c, &g);
        let results: Vec<Result<Vec<u8>, CallErr>> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..16).map(|t| s.spawn(move || cr.renew_raw(gr, &format!("op-{round}-{t}")))).collect();
            let f = s.spawn(|| c.finalize());
            f.join().unwrap().unwrap();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let ok = results.iter().filter(|r| r.is_ok()).count();
        assert!(ok <= 1, "round {round}: {ok} replies released");
        let after: Vec<_> = (0..8).map(|t| c.renew_raw(&g, &format!("late-{t}"))).collect();
        assert!(after.iter().all(|r| *r == Err(CallErr::Api(410, "closed".into()))), "{after:?}");
        assert_eq!(c.fetch_grant().unwrap_err(), CallErr::Api(410, "closed".into()));
        let ctl: Value = serde_json::from_slice(&st.store().dump()[&format!("ctl/{}", c.session)]).unwrap();
        for f in ["commit", "prev_commit", "receipt", "saved_reply", "claim_op", "saved_op"] {
            assert_eq!(ctl[f], "", "round {round}: {f} survived closure");
        }
        let calls = st.family_calls()[0];
        assert!(calls >= ok as u64 && calls <= 1, "round {round}: {calls} provider calls");
        assert_eq!(st.revocations(), 2 * (calls - ok as u64), "round {round}: tokens minted for a refused commit must be revoked");
    }
}

#[test]
fn crash_after_commit_before_reply_keeps_the_reply_replayable() {
    let dir = temp_dir("crash3");
    let mut st = Stack::with_file(3600, &dir.join("s.json"));
    let tr = Arc::new(DropReply::default());
    let (mut c, g0) = st.onboard_with(tr.clone());
    *tr.arm.lock().unwrap() = true;
    assert!(matches!(c.renew_raw(&g0, "op-1"), Err(CallErr::Transport(_))));
    let first = tr.captured.lock().unwrap()[0].clone();
    st.restart();
    st.repoint(&mut c);
    assert_eq!(c.renew_raw(&g0, "op-1").unwrap(), first, "identical reply after a restart");
    assert_eq!(st.family_calls(), vec![1]);
    assert!(c.renew_raw(&g0, "op-2").is_err(), "another operation cannot take the same generation");
    assert_eq!(st.family_calls(), vec![1]);
    let g1 = c.open_grant(&serde_json::from_slice(&first).unwrap(), Some(&g0.refresh)).unwrap();
    assert_eq!(st.whoami(&g1.access), 200);
    assert_eq!(c.renew(&g1, "op-3").unwrap().generation, 2);
    std::fs::remove_dir_all(dir).ok();
}

#[derive(Default)]
struct DropReply {
    arm: Mutex<bool>,
    captured: Mutex<Vec<Vec<u8>>>,
}

impl Transport for DropReply {
    fn call(&self, m: &str, u: &str, h: &[(&str, &str)], b: &[u8]) -> Result<(u16, Vec<u8>), Error> {
        let r = (Ureq { redirects: 0 }).call(m, u, h, b)?;
        let mut arm = self.arm.lock().unwrap();
        if *arm && u.ends_with("/renew") {
            *arm = false;
            self.captured.lock().unwrap().push(r.1);
            return Err(Error("reply dropped".into()));
        }
        Ok(r)
    }
}

fn assert_needs_fresh_consent(st: &Stack, c: &Client, g: &Grant, calls: u64) {
    for op in ["op-1", "op-2", "op-1"] {
        assert_eq!(c.renew_raw(g, op), Err(CallErr::Api(409, "recovery_required".into())), "op {op}");
    }
    assert!(c.renew_recoverable(g, 2, Duration::from_millis(1)).is_err());
    assert_eq!(st.family_calls(), vec![calls], "no further provider call");
    let (fresh, fg) = st.onboard();
    assert_eq!(fresh.renew(&fg, "op-fresh").unwrap().generation, 1, "a fresh consent works");
}

#[test]
fn crash_after_reservation_before_the_provider_call_needs_fresh_consent() {
    let dir = temp_dir("crash1");
    let mut st = Stack::with_file(3600, &dir.join("s.json"));
    let (mut c, g0) = st.onboard();
    let q = BeginReq { session: &c.session, op: "op-1", gen: 0, receipt: &g0.receipt, token: &g0.refresh };
    assert!(matches!(st.broker().renewer.begin(&q), Ok(BeginOut::Reserved(_))));
    st.restart();
    st.repoint(&mut c);
    assert_needs_fresh_consent(&st, &c, &g0, 0);
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn crash_after_the_provider_call_before_commit_needs_fresh_consent() {
    let dir = temp_dir("crash2");
    let mut st = Stack::with_file(3600, &dir.join("s.json"));
    let (mut c, g0) = st.onboard();
    (Ureq { redirects: 0 }).call("POST", &format!("{}/debug/fault?drop_refresh=1", st.prov.url()), &[], &[]).unwrap();
    assert_eq!(c.renew_raw(&g0, "op-1"), Err(CallErr::Api(502, "provider_unavailable".into())));
    assert_eq!(st.family_calls(), vec![1]);
    st.restart();
    st.repoint(&mut c);
    assert_needs_fresh_consent(&st, &c, &g0, 1);
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn damaged_store_files_fail_closed() {
    let dir = temp_dir("store");
    let good = dir.join("good.json");
    {
        let st = Stack::with_file(3600, &good);
        st.onboard();
    }
    let raw = std::fs::read(&good).unwrap();
    assert!(raw.len() > 100);
    let mut cases: Vec<(String, Vec<u8>)> = vec![
        ("empty".into(), vec![]),
        ("garbage".into(), b"\x00\xff\xfe not json at all".to_vec()),
        ("array".into(), b"[1,2,3]".to_vec()),
        ("wrong value type".into(), br#"{"a":1}"#.to_vec()),
        ("bad base64".into(), br#"{"sess/x":"@@@@"}"#.to_vec()),
    ];
    for cut in [1, raw.len() / 3, raw.len() / 2, raw.len() - 1] {
        cases.push((format!("truncated to {cut}"), raw[..cut].to_vec()));
    }
    for (name, bytes) in &cases {
        let p = dir.join("bad.json");
        std::fs::write(&p, bytes).unwrap();
        assert!(MemStore::open_file(&p).is_err(), "{name}: opened");
        let mut d = Proc::spawn(
            &dir,
            "scoutd-bad",
            "scoutd",
            &[
                "--store-file",
                p.to_str().unwrap(),
                "--provider-auth-url",
                "http://127.0.0.1:1/a",
                "--provider-token-url",
                "http://127.0.0.1:1/t",
            ],
            &[("SCOUT_CLIENT_SECRET", "client-secret-aaaaaaaaaa"), ("SCOUT_COMMIT_KEY", "commit-key-bbbbbbbbbbbbbb")],
        );
        assert_eq!(d.wait(Duration::from_secs(10)), Some(1), "{name}: scoutd must refuse to start");
        let t = d.text();
        assert!(t.contains("scoutd: store:") && !t.contains("panicked"), "{name}: {t}");
    }
    // Valid container, unreadable records: nothing is served from them.
    let p = dir.join("junk-records.json");
    let junk = format!("{{\"sess/abc\":\"{}\",\"ctl/abc\":\"{}\"}}", b64(b"not a record"), b64(b"{}"));
    std::fs::write(&p, junk).unwrap();
    let st = Stack::with_file(3600, &p);
    let (s, v) = post(&format!("{}/v1/sessions/abc/status", st.url()), &json!({}));
    assert!(s == 404 || s == 400, "{s} {v}");
    let (s, _) = post(&format!("{}/v1/sessions/abc/finalize", st.url()), &json!({ "secret": "x" }));
    assert_eq!(s, 404);
    let tmp_left = std::fs::read_dir(&dir).unwrap().filter_map(Result::ok).any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
    assert!(!tmp_left, "temporary files left behind");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_failed_write_rolls_back_and_leaves_no_temp_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("persist");
    let p = dir.join("s.json");
    let s = MemStore::open_file(&p).unwrap();
    s.update("a", &mut |_| Some(b"1".to_vec())).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let probe = std::fs::File::create(dir.join("probe"));
    if probe.is_ok() {
        std::fs::remove_file(dir.join("probe")).ok();
        println!("skipped: directory permissions are not enforced for this user");
    } else {
        assert!(s.update("a", &mut |_| Some(b"2".to_vec())).is_err());
        assert_eq!(s.get("a").unwrap().unwrap(), b"1", "memory must roll back with the file");
        assert!(s.delete("a").is_err());
        assert_eq!(s.get("a").unwrap().unwrap(), b"1");
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let left =
        std::fs::read_dir(&dir).unwrap().filter_map(Result::ok).filter(|e| e.file_name().to_string_lossy().ends_with(".tmp")).count();
    assert_eq!(left, 0);
    drop(s);
    assert_eq!(MemStore::open_file(&p).unwrap().get("a").unwrap().unwrap(), b"1");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn finalize_racing_a_callback_leaves_the_closed_marker() {
    let slot: Arc<Mutex<Option<(String, String, String)>>> = Arc::new(Mutex::new(None));
    let s2 = slot.clone();
    let hook = Arc::new(Hook {
        suffix: "/token",
        hook: Mutex::new(Some(Box::new(move || {
            let (base, id, secret) = s2.lock().unwrap().clone().unwrap();
            let (s, _) = post(&format!("{base}/v1/sessions/{id}/finalize"), &json!({ "secret": secret }));
            assert_eq!(s, 200);
        }))),
    });
    let st = Stack::with_transport(hook);
    let mut c = Client::with_ureq(&st.url());
    c.create(3600).unwrap();
    *slot.lock().unwrap() = Some((st.url(), c.session.clone(), c.secret.clone()));
    let (s, _) = (Ureq { redirects: 5 }).call("GET", &c.consent_url("alice"), &[], &[]).unwrap();
    assert!(s >= 400, "the callback must fail once the session was closed under it, got {s}");
    let ctl: Value = serde_json::from_slice(&st.store().dump()[&format!("ctl/{}", c.session)]).unwrap();
    assert_eq!(ctl["ctl"]["phase"], "Closed", "closed marker must survive the failed callback");
    assert_eq!(c.status().unwrap_err(), CallErr::Api(410, "closed".into()));
    assert!(st.revocations() >= 2, "tokens minted by the failed callback must be revoked");
}

#[test]
fn oversized_bodies_and_idle_connections_are_bounded() {
    let st = Stack::new();
    let target = format!("{}/v1/sessions", st.url());
    let big = vec![b' '; (1 << 20) + 1];
    assert!(post_bytes(&target, &big).map(|r| r.0 >= 400).unwrap_or(true));
    let ok = {
        let mut b = br#"{"capability":""#.to_vec();
        b.extend(vec![b'a'; (1 << 20) - 100]);
        b.extend_from_slice(br#""}"#);
        b
    };
    assert_eq!(post_bytes(&target, &ok).unwrap().0, 200, "a body under the cap is accepted");
    for decl in ["4294967296", "18446744073709551615", "-1", "1e9"] {
        let mut s = TcpStream::connect(st.srv().addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(format!("POST /v1/sessions HTTP/1.1\r\nContent-Length: {decl}\r\n\r\n{{}}").as_bytes()).unwrap();
        let mut out = vec![];
        let _ = s.read_to_end(&mut out);
        assert!(!out.starts_with(b"HTTP/1.1 200"), "Content-Length {decl} was served");
    }
    let idle: Vec<TcpStream> = (0..200).map(|_| TcpStream::connect(st.srv().addr).unwrap()).collect();
    let t = std::time::Instant::now();
    st.onboard();
    assert!(t.elapsed() < Duration::from_secs(10));
    println!("200 idle connections held; a full onboarding still took {:?} (no connection cap exists)", t.elapsed());
    drop(idle);
}

#[test]
fn store_file_is_private_and_exclusive() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("lock");
    let p = dir.join("s.json");
    let a = MemStore::open_file(&p).unwrap();
    a.update("k", &mut |_| Some(b"v".to_vec())).unwrap();
    let mode = |f: &std::path::Path| std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&p), 0o600, "store file");
    assert_eq!(mode(&dir.join("s.json.lock")), 0o600, "lock file");
    let err = MemStore::open_file(&p).err().expect("a second open of the same file must fail").0;
    assert!(err.contains("in use"), "{err}");
    let mut second = Proc::spawn(
        &dir,
        "second",
        "scoutd",
        &[
            "--store-file",
            p.to_str().unwrap(),
            "--provider-auth-url",
            "http://127.0.0.1:1/a",
            "--provider-token-url",
            "http://127.0.0.1:1/t",
        ],
        &[("SCOUT_CLIENT_SECRET", "client-secret-aaaaaaaaaa"), ("SCOUT_COMMIT_KEY", "commit-key-bbbbbbbbbbbbbb")],
    );
    assert_eq!(second.wait(Duration::from_secs(10)), Some(1));
    assert!(second.text().contains("in use"));
    drop(a);
    let b = MemStore::open_file(&p).unwrap();
    assert_eq!(b.get("k").unwrap().unwrap(), b"v");
    std::fs::remove_dir_all(dir).ok();
}
