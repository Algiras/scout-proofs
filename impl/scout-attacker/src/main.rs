// SPDX-License-Identifier: Apache-2.0

//! Runs against a live broker and provider with a legitimate session of its own, a stolen refresh token
//! and the victim's session id, and tries to misuse them. Exits 0 only if every attack was refused.
#![forbid(unsafe_code)]

use scout_runner::{CallErr, Client, Grant};
use scout_wire::http::{Transport, Ureq};
use scout_wire::{arg, arg_or, b64, Error};
use serde_json::{json, Value};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Capture(Mutex<Vec<(String, Vec<u8>)>>);

impl Transport for Capture {
    fn call(&self, m: &str, u: &str, h: &[(&str, &str)], b: &[u8]) -> Result<(u16, Vec<u8>), Error> {
        if let Ok(mut v) = self.0.lock() {
            v.push((u.to_string(), b.to_vec()));
        }
        (Ureq { redirects: 0 }).call(m, u, h, b)
    }
}

struct Ctx {
    broker: String,
    front: String,
    back: Option<String>,
    me: Client,
    cap: Arc<Capture>,
    grant: Grant,
    leak: Value,
    victim: String,
    shared: PathBuf,
}

enum Verdict {
    Refused,
    Allowed(String),
    Skipped(&'static str),
}

/// A clean refusal is a 4xx answer; success or a server error is not.
fn refusal(status: u16, body: &[u8]) -> Result<(), String> {
    if (400..500).contains(&status) {
        Ok(())
    } else {
        Err(format!("answered {status}: {}", String::from_utf8_lossy(&body[..body.len().min(120)])))
    }
}

fn post(url: &str, body: &Value) -> Result<(u16, Vec<u8>), String> {
    (Ureq { redirects: 0 })
        .call("POST", url, &[("Content-Type", "application/json")], &serde_json::to_vec(body).unwrap_or_default())
        .map_err(|e| e.to_string())
}

fn call_refused<T: std::fmt::Debug>(r: Result<T, CallErr>) -> Result<(), String> {
    match r {
        Err(CallErr::Api(s, _)) if (400..500).contains(&s) => Ok(()),
        other => Err(format!("{other:?}")),
    }
}

fn all(results: Vec<Result<(), String>>) -> Verdict {
    match results.into_iter().find_map(Result::err) {
        None => Verdict::Refused,
        Some(e) => Verdict::Allowed(e),
    }
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// Proof signed by this attacker's key but naming the victim's session and route.
fn proof_for_victim(c: &mut Ctx, op: &str, extra: Value) -> (String, Value) {
    let own = std::mem::replace(&mut c.me.session, c.victim.clone());
    let route = c.me.route(op);
    let proof = c.me.proof(&route, extra);
    c.me.session = own;
    (format!("{}{route}", c.broker), json!(proof))
}

fn read_victim_grants(c: &mut Ctx) -> Verdict {
    let (url, proof) = proof_for_victim(c, "grant", json!({}));
    let mine = c.me.proof(&c.me.route("grant"), json!({}));
    let own_at_victim = post(&url, &json!({ "proof": mine }));
    all(vec![post(&url, &json!({ "proof": proof })).and_then(|(st, b)| refusal(st, &b)), own_at_victim.and_then(|(st, b)| refusal(st, &b))])
}

fn bind_without_secret(c: &mut Ctx) -> Verdict {
    let url = format!("{}/v1/sessions/{}/bind", c.broker, c.victim);
    let keys = json!({ "encPub": b64(&c.me.enc_pub), "sigPub": b64(&c.me.sig_pub()) });
    let mut results = vec![];
    for secret in [json!(""), json!("guess"), json!(c.me.secret), json!(null)] {
        let mut body = keys.clone();
        body["secret"] = secret;
        results.push(post(&url, &body).and_then(|(st, b)| refusal(st, &b)));
    }
    all(results)
}

fn renew_with_stolen_refresh(c: &mut Ctx) -> Verdict {
    let stolen = s(&c.leak["refresh"]);
    let own_receipt = Grant { refresh: stolen.clone(), ..c.grant.clone() };
    let their_receipt = Grant {
        refresh: stolen,
        receipt: s(&c.leak["receipt"]),
        generation: c.leak["generation"].as_u64().unwrap_or(0) as u32,
        ..c.grant.clone()
    };
    all(vec![call_refused(c.me.renew_raw(&own_receipt, "steal-1")), call_refused(c.me.renew_raw(&their_receipt, "steal-2"))])
}

fn renew_victim_session(c: &mut Ctx) -> Verdict {
    let refresh = s(&c.leak["refresh"]);
    let extra = json!({ "capability": c.me.capability, "generation": c.leak["generation"], "receipt": c.leak["receipt"],
                        "refreshHash": scout_wire::commit::sha256_hex(refresh.as_bytes()), "operationId": "takeover" });
    let (url, proof) = proof_for_victim(c, "renew", extra);
    all(vec![post(&url, &json!({ "proof": proof, "refreshToken": refresh })).and_then(|(st, b)| refusal(st, &b))])
}

fn replay_with_other_operation(c: &mut Ctx) -> Verdict {
    let g0 = c.grant.clone();
    let g1 = match c.me.renew(&g0, "op-A") {
        Ok(g) => g,
        Err(e) => return Verdict::Allowed(format!("own legitimate renewal failed: {e}")),
    };
    let captured = match c.cap.0.lock().ok().and_then(|v| v.iter().rev().find(|(u, _)| u.ends_with("/renew")).cloned()) {
        Some(x) => x,
        None => return Verdict::Allowed("no captured request".into()),
    };
    let mut edited: Value = serde_json::from_slice(&captured.1).unwrap_or(Value::Null);
    edited["proof"]["body"]["operationId"] = json!("op-B");
    let tampered = post(&captured.0, &edited).and_then(|(st, b)| refusal(st, &b));
    let resigned = call_refused(c.me.renew_raw(&g0, "op-B"));
    c.grant = g1;
    all(vec![tampered, resigned])
}

fn revoke_undelivered(c: &mut Ctx) -> Verdict {
    let stolen = s(&c.leak["refresh"]);
    all(vec![call_refused(c.me.revoke(&[("refresh", &stolen)])), call_refused(c.me.revoke(&[("access", "at_not_delivered")]))])
}

/// `--provider-back` is a comma-separated list of addresses where the token endpoint might be reachable.
fn backchannel_direct(c: &mut Ctx) -> Verdict {
    let Some(back) = &c.back else { return Verdict::Skipped("no back channel address configured") };
    for host in back.split(',').map(|h| h.trim().trim_start_matches("http://").trim_end_matches('/')).filter(|h| !h.is_empty()) {
        let addrs: Vec<_> = host.to_socket_addrs().map(|a| a.collect()).unwrap_or_default();
        if addrs.iter().any(|a| TcpStream::connect_timeout(a, Duration::from_secs(3)).is_ok()) {
            return Verdict::Allowed(format!("connected to {host}"));
        }
    }
    Verdict::Refused
}

fn provider_without_client_secret(c: &mut Ctx) -> Verdict {
    let stolen = s(&c.leak["refresh"]);
    let form = |fields: &[(&str, &str)]| -> Vec<u8> {
        fields
            .iter()
            .map(|(k, v)| format!("{}={}", scout_wire::http::urlencode(k), scout_wire::http::urlencode(v)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes()
    };
    let hdr = [("Content-Type", "application/x-www-form-urlencoded")];
    let mut results = vec![];
    for (path, fields) in [
        ("/token", vec![("grant_type", "refresh_token"), ("refresh_token", stolen.as_str()), ("client_id", "scout-demo")]),
        ("/token", vec![("grant_type", "refresh_token"), ("refresh_token", stolen.as_str())]),
        ("/revoke", vec![("token", stolen.as_str()), ("client_id", "scout-demo")]),
    ] {
        let r = (Ureq { redirects: 0 }).call("POST", &format!("{}{path}", c.front), &hdr, &form(&fields)).map_err(|e| e.to_string());
        results.push(r.and_then(|(st, b)| refusal(st, &b)));
    }
    all(results)
}

fn fetch_after_finalization(c: &mut Ctx) -> Verdict {
    let g = c.grant.clone();
    if let Err(e) = c.me.revoke(&[("access", &g.access), ("refresh", &g.refresh)]) {
        return Verdict::Allowed(format!("own revocation failed: {e}"));
    }
    if let Err(e) = c.me.finalize() {
        return Verdict::Allowed(format!("own finalization failed: {e}"));
    }
    all(vec![call_refused(c.me.fetch_grant()), call_refused(c.me.renew_raw(&g, "after-close")), call_refused(c.me.status())])
}

fn victim_unaffected(c: &mut Ctx) -> Verdict {
    let limit: u64 = arg_or("victim-timeout", "120").parse().unwrap_or(120);
    let end = Instant::now() + Duration::from_secs(limit);
    while Instant::now() < end {
        if let Ok(t) = std::fs::read_to_string(c.shared.join("victim.result")) {
            return if t.trim() == "ok" { Verdict::Refused } else { Verdict::Allowed(format!("the victim failed: {t}")) };
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Verdict::Allowed("the victim did not finish in time".into())
}

fn wait_for(path: &std::path::Path, secs: u64) -> Option<String> {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if let Ok(t) = std::fs::read_to_string(path) {
            return Some(t);
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    None
}

fn setup() -> Result<Ctx, String> {
    let broker = arg("broker").ok_or("--broker is required")?;
    let front = arg("provider-front").ok_or("--provider-front is required")?;
    let shared = PathBuf::from(arg_or("shared", "/shared"));
    let cap = Arc::new(Capture::default());
    let mut me = Client::new(&broker, cap.clone());
    let mut created = Err("not attempted".to_string());
    for _ in 0..60 {
        created = me.create(3600).map_err(|e| e.to_string());
        if created.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    created?;
    (Ureq { redirects: 5 }).call("GET", &me.consent_url("attacker"), &[], &[]).map_err(|e| e.to_string())?;
    let grant = me.fetch_grant().map_err(|e| format!("own grant: {e}"))?;
    let status = me.status().map_err(|e| format!("own status: {e}"))?;
    if status.state != "ACTIVE" {
        return Err(format!("own session is {}", status.state));
    }
    let raw = wait_for(&shared.join("leak.json"), 90).ok_or("the victim never leaked a token")?;
    let leak: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let victim = s(&leak["session"]);
    if victim.is_empty() || victim == me.session {
        return Err("bad leak file".into());
    }
    Ok(Ctx { broker, front, back: arg("provider-back").filter(|b| !b.is_empty()), me, cap, grant, leak, victim, shared })
}

fn main() {
    let mut c = match setup() {
        Ok(c) => c,
        Err(e) => {
            println!("CONTROL FAILED: {e}");
            std::process::exit(2);
        }
    };
    type Attack = fn(&mut Ctx) -> Verdict;
    let attacks: [(&str, Attack); 10] = [
        ("read-victim-grants", read_victim_grants),
        ("bind-victim-session-without-secret", bind_without_secret),
        ("renew-with-stolen-refresh-token", renew_with_stolen_refresh),
        ("renew-victim-session", renew_victim_session),
        ("replay-own-renewal-with-other-operation", replay_with_other_operation),
        ("revoke-token-not-delivered-to-session", revoke_undelivered),
        ("reach-provider-back-channel-directly", backchannel_direct),
        ("provider-front-channel-without-client-secret", provider_without_client_secret),
        ("fetch-after-finalization", fetch_after_finalization),
        ("victim-session-completes-unharmed", victim_unaffected),
    ];
    let (mut refused, mut run) = (0, 0);
    for (name, f) in attacks {
        match f(&mut c) {
            Verdict::Refused => {
                refused += 1;
                run += 1;
                println!("PASS {name}");
            }
            Verdict::Allowed(why) => {
                run += 1;
                println!("FAIL {name}: {why}");
            }
            Verdict::Skipped(why) => println!("SKIP {name}: {why}"),
        }
    }
    println!("ATTACKS REFUSED {refused}/{run}");
    std::process::exit(i32::from(refused != run));
}
