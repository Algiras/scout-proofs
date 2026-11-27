// SPDX-License-Identifier: Apache-2.0

//! End-to-end: real broker, mock provider and runner client over local HTTP.
use scout_broker::provider::Provider;
use scout_broker::renewal::{BeginOut, BeginReq, RenewErr, Renewer};
use scout_broker::server::{Broker, Config};
use scout_broker::store::{MemStore, Store};
use scout_core::Reject;
use scout_mockprovider::Config as PConfig;
use scout_runner::{CallErr, Client, Grant};
use scout_wire::http::{serve, Handler, Server, Transport, Ureq};
use scout_wire::{b64, now_secs, Error};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};

struct Env {
    prov: Server,
    srv: Server,
    broker: Arc<Broker>,
    store: Arc<MemStore>,
}

fn setup_with(access_ttl: u64, store: Arc<MemStore>) -> Env {
    let prov = scout_mockprovider::start(
        "127.0.0.1:0",
        PConfig { client_id: "scout-demo".into(), client_secret: "client-secret-xyz".into(), auto_approve: true, access_ttl },
    )
    .unwrap();
    let cell: Arc<OnceLock<Arc<Broker>>> = Arc::new(OnceLock::new());
    let c2 = cell.clone();
    let h: Handler = Arc::new(move |r| c2.get().and_then(|b| b.handler()(r)));
    let srv = serve("127.0.0.1:0", h).unwrap();
    let base = srv.url();
    let provider = Provider {
        auth_url: format!("{}/authorize", prov.url()),
        token_url: format!("{}/token", prov.url()),
        revoke_url: Some(format!("{}/revoke", prov.url())),
        client_id: "scout-demo".into(),
        client_secret: "client-secret-xyz".into(),
        scope: "read".into(),
        transport: Arc::new(Ureq { redirects: 0 }),
    };
    let renewer = Renewer::new(store.clone(), b"commit-key-0123456789abcdef".to_vec(), "scout-demo", Arc::new(now_secs));
    let cfg = Config { authority: base.trim_start_matches("http://").to_string(), public_base: base, default_ttl: 3600, max_ttl: 86400 };
    let broker = Arc::new(Broker { cfg, store: store.clone(), renewer, provider });
    cell.set(broker.clone()).ok();
    Env { prov, srv, broker, store }
}

fn setup() -> Env {
    setup_with(3600, Arc::new(MemStore::new()))
}

fn get(url: &str, bearer: Option<&str>) -> (u16, Value) {
    let auth = bearer.map(|b| format!("Bearer {b}")).unwrap_or_default();
    let hdr: Vec<(&str, &str)> = if bearer.is_some() { vec![("Authorization", auth.as_str())] } else { vec![] };
    let (s, b) = (Ureq { redirects: 0 }).call("GET", url, &hdr, &[]).unwrap();
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

fn family_calls(env: &Env) -> Vec<u64> {
    let (_, v) = get(&format!("{}/debug/stats", env.prov.url()), None);
    v["families"].as_array().unwrap().iter().map(|f| f["refreshCalls"].as_u64().unwrap()).collect()
}

fn revocations(env: &Env) -> u64 {
    get(&format!("{}/debug/stats", env.prov.url()), None).1["revocations"].as_u64().unwrap()
}

fn post_fault(env: &Env, n: u32) {
    (Ureq { redirects: 0 }).call("POST", &format!("{}/debug/fault?drop_refresh={n}", env.prov.url()), &[], &[]).unwrap();
}

fn whoami(env: &Env, tok: &str) -> u16 {
    get(&format!("{}/api/whoami", env.prov.url()), Some(tok)).0
}

/// Forwards every call; for one marked route, drops the reply after the server acted.
#[derive(Default)]
struct DropReply {
    arm: Mutex<Option<String>>,
    captured: Mutex<Vec<Vec<u8>>>,
}

impl Transport for DropReply {
    fn call(&self, m: &str, url: &str, h: &[(&str, &str)], b: &[u8]) -> Result<(u16, Vec<u8>), Error> {
        let r = (Ureq { redirects: 0 }).call(m, url, h, b)?;
        let mut arm = self.arm.lock().unwrap();
        if arm.as_deref().is_some_and(|p| url.ends_with(p)) {
            *arm = None;
            self.captured.lock().unwrap().push(r.1);
            return Err(Error("reply dropped".into()));
        }
        Ok(r)
    }
}

fn onboard_with(env: &Env, tr: Arc<dyn Transport>) -> (Client, Grant) {
    let mut c = Client::new(&env.srv.url(), tr);
    c.create(3600).unwrap();
    let (s, _) = (Ureq { redirects: 5 }).call("GET", &c.consent_url("alice"), &[], &[]).unwrap();
    assert_eq!(s, 200);
    assert_eq!(c.status().unwrap().state, "AUTHORIZED");
    let g = c.fetch_grant().unwrap();
    assert_eq!(c.status().unwrap().state, "ACTIVE");
    (c, g)
}

fn onboard(env: &Env) -> (Client, Grant) {
    onboard_with(env, Arc::new(Ureq { redirects: 0 }))
}

#[test]
fn happy_path_renewal_and_teardown() {
    let env = setup();
    let (c, g0) = onboard(&env);
    assert_eq!(whoami(&env, &g0.access), 200);
    let g1 = c.renew(&g0, "op-1").unwrap();
    assert_eq!(g1.generation, 1);
    assert_ne!(g1.refresh, g0.refresh);
    assert_eq!(whoami(&env, &g1.access), 200);
    assert_eq!(family_calls(&env), vec![1]);
    // The rotated-away refresh token is dead at the provider and unusable here.
    assert!(c.renew(&g0, "op-2").is_err());
    let out = c.revoke(&[("access", &g1.access), ("refresh", &g1.refresh)]).unwrap();
    assert!(out.iter().all(|(_, o)| o == "acknowledged"), "{out:?}");
    assert_eq!(whoami(&env, &g1.access), 401);
    c.finalize().unwrap();
    assert!(matches!(c.status(), Err(CallErr::Api(410, _))));
    c.finalize().unwrap();
}

#[test]
fn lost_reply_returns_identical_ciphertext_with_one_exchange() {
    let env = setup();
    let tr = Arc::new(DropReply::default());
    let (c, g0) = onboard_with(&env, tr.clone());
    *tr.arm.lock().unwrap() = Some("/renew".into());
    assert!(matches!(c.renew_raw(&g0, "op-1"), Err(CallErr::Transport(_))));
    let first = tr.captured.lock().unwrap()[0].clone();
    let retry = c.renew_raw(&g0, "op-1").unwrap();
    assert_eq!(first, retry, "retry must return the identical ciphertext");
    assert_eq!(family_calls(&env), vec![1], "exactly one provider exchange");
    let v: Value = serde_json::from_slice(&retry).unwrap();
    let g1 = c.open_grant(&v, Some(&g0.refresh)).unwrap();
    assert_eq!(whoami(&env, &g1.access), 200);
    // Admitting the next generation retires the saved reply.
    let g2 = c.renew(&g1, "op-2").unwrap();
    assert_eq!(g2.generation, 2);
    assert!(c.renew_raw(&g0, "op-1").is_err());
    assert_eq!(family_calls(&env), vec![2]);
}

#[test]
fn competing_operation_is_rejected() {
    let env = setup();
    let (c, g0) = onboard(&env);
    let q = |op| BeginReq { session: &c.session, op, gen: 0, receipt: &g0.receipt, token: &g0.refresh };
    assert!(matches!(env.broker.renewer.begin(&q("op-A")), Ok(BeginOut::Reserved(_))));
    assert_eq!(c.renew_raw(&g0, "op-B"), Err(CallErr::Api(409, "competing_operation".into())));
    assert_eq!(c.renew_raw(&g0, "op-A"), Err(CallErr::Api(409, "in_progress".into())));
    assert_eq!(family_calls(&env), vec![0]);
}

#[test]
fn ambiguous_outcome_needs_fresh_consent_and_never_retries_the_provider() {
    let env = setup();
    let (c, g0) = onboard(&env);
    post_fault(&env, 1);
    assert_eq!(c.renew_raw(&g0, "op-A"), Err(CallErr::Api(502, "provider_unavailable".into())));
    assert_eq!(family_calls(&env), vec![1]);
    for op in ["op-A", "op-B", "op-A"] {
        assert_eq!(c.renew_raw(&g0, op), Err(CallErr::Api(409, "recovery_required".into())));
    }
    assert_eq!(family_calls(&env), vec![1], "no further provider call");
    // The runner stops retrying and treats the capability as needing consent.
    assert!(c.renew_recoverable(&g0, 3, std::time::Duration::from_millis(1)).is_err());
    assert_eq!(family_calls(&env), vec![1]);
}

#[test]
fn foreign_token_is_rejected_without_a_provider_call() {
    let env = setup();
    let (a, ga) = onboard(&env);
    let (_b, gb) = onboard(&env);
    let foreign = Grant { refresh: gb.refresh.clone(), ..ga.clone() };
    assert_eq!(a.renew_raw(&foreign, "op-1"), Err(CallErr::Api(403, "commitment_mismatch".into())));
    assert_eq!(family_calls(&env), vec![0, 0]);
    // The rejection did not consume the reservation.
    assert_eq!(a.renew(&ga, "op-2").unwrap().generation, 1);
}

#[test]
fn storage_snapshot_holds_no_token_plaintext() {
    let env = setup();
    let (c, g0) = onboard(&env);
    let g1 = c.renew(&g0, "op-1").unwrap();
    let dump = env.store.dump();
    assert!(!dump.is_empty());
    let mut secrets = vec![c.secret.clone()];
    for g in [&g0, &g1] {
        secrets.extend([g.access.clone(), g.refresh.clone()]);
    }
    let all: Vec<u8> = dump.values().flat_map(|v| v.clone()).collect();
    for s in secrets {
        for needle in [s.clone().into_bytes(), b64(s.as_bytes()).into_bytes()] {
            assert!(!all.windows(needle.len()).any(|w| w == needle.as_slice()), "plaintext {s} in store");
        }
    }
    assert!(!String::from_utf8_lossy(&all).contains("client-secret-xyz"));
}

#[test]
fn closure_blocks_renewal_replay_and_delivery() {
    let env = setup();
    let tr = Arc::new(DropReply::default());
    let (c, g0) = onboard_with(&env, tr.clone());
    *tr.arm.lock().unwrap() = Some("/renew".into());
    let _ = c.renew_raw(&g0, "op-1");
    c.revoke(&[("access", &g0.access), ("refresh", &g0.refresh)]).ok();
    c.finalize().unwrap();
    for r in [c.renew_raw(&g0, "op-1"), c.renew_raw(&g0, "op-2")] {
        assert_eq!(r, Err(CallErr::Api(410, "closed".into())));
    }
    assert_eq!(c.fetch_grant().unwrap_err(), CallErr::Api(410, "closed".into()));
    let ctl: Value = serde_json::from_slice(&env.store.dump()[&format!("ctl/{}", c.session)]).unwrap();
    for f in ["commit", "prev_commit", "receipt", "initial_grant", "saved_reply", "claim_op"] {
        assert_eq!(ctl[f], "", "{f} must be empty after closure");
    }
    assert!(!env.store.dump().contains_key(&format!("sess/{}", c.session)));
    assert_eq!(ctl["ctl"]["phase"], "Closed");
}

#[test]
fn revoking_an_undelivered_token_is_refused() {
    let env = setup();
    let (a, _ga) = onboard(&env);
    let (_b, gb) = onboard(&env);
    let r = a.revoke(&[("access", &gb.access)]);
    assert_eq!(r, Err(CallErr::Api(403, "not_delivered".into())));
    assert_eq!(a.revoke(&[("access", "at_made_up")]), Err(CallErr::Api(403, "not_delivered".into())));
    assert_eq!(revocations(&env), 0);
    assert_eq!(whoami(&env, &gb.access), 200);
}

#[test]
fn delivery_record_replays_identical_requests_and_revokes_on_a_different_one() {
    let env = setup();
    let mut c = Client::with_ureq(&env.srv.url());
    c.create(3600).unwrap();
    (Ureq { redirects: 5 }).call("GET", &c.consent_url("alice"), &[], &[]).unwrap();
    let route = c.route("grant");
    let body = serde_json::to_vec(&json!({ "proof": c.proof(&route, json!({})) })).unwrap();
    let url = format!("{}{}", c.base, route);
    let t = Ureq { redirects: 0 };
    let first = t.call("POST", &url, &[], &body).unwrap();
    let again = t.call("POST", &url, &[], &body).unwrap();
    assert_eq!((first.0, again.0), (200, 200));
    assert_eq!(first.1, again.1);
    assert_eq!(c.fetch_grant().unwrap_err(), CallErr::Api(409, "delivery_conflict".into()));
    assert_eq!(c.status().unwrap().state, "REVOKED");
    assert_eq!(t.call("POST", &url, &[], &body).unwrap().0, 409);
}

#[test]
fn bind_before_mint_and_principal_lock() {
    let env = setup();
    let mut req = Client::with_ureq(&env.srv.url());
    req.create_unbound(3600).unwrap();
    let t = Ureq { redirects: 0 };
    assert_eq!(t.call("GET", &req.consent_url("alice"), &[], &[]).unwrap().0, 409);
    let mut runner = Client::with_ureq(&env.srv.url());
    assert_eq!(runner.bind(&req.session, "wrong-secret").unwrap_err(), CallErr::Api(403, "bad_secret".into()));
    runner.bind(&req.session, &req.secret).unwrap();
    assert_eq!(t.call("GET", &runner.consent_url("alice"), &[], &[]).unwrap().0, 302);
    assert_eq!(t.call("GET", &runner.consent_url("bob"), &[], &[]).unwrap().0, 403);
    assert_eq!(runner.bind(&req.session, &req.secret).unwrap_err().code(), "bad_state");
}

#[test]
fn state_survives_a_broker_restart() {
    let dir = std::env::temp_dir().join(format!("scout-e2e-{}", scout_wire::random_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("store.json");
    let env = setup_with(3600, Arc::new(MemStore::open_file(&path).unwrap()));
    let tr = Arc::new(DropReply::default());
    let (c, g0) = onboard_with(&env, tr.clone());
    *tr.arm.lock().unwrap() = Some("/renew".into());
    let _ = c.renew_raw(&g0, "op-1");
    let first = tr.captured.lock().unwrap()[0].clone();
    // A new process over the same file (the old broker is gone, and with it the file lock).
    drop(env);
    let store2: Arc<dyn Store> = (0..100)
        .find_map(|_| {
            MemStore::open_file(&path).ok().map(|s| Arc::new(s) as Arc<dyn Store>).or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                None
            })
        })
        .expect("store file released");
    let r2 = Renewer::new(store2, b"commit-key-0123456789abcdef".to_vec(), "scout-demo", Arc::new(now_secs));
    let q = BeginReq { session: &c.session, op: "op-1", gen: 0, receipt: &g0.receipt, token: &g0.refresh };
    assert_eq!(r2.begin(&q), Ok(BeginOut::Replay(first)));
    // A reservation without a result is not released by a restart either.
    let q2 = BeginReq { session: &c.session, op: "op-9", gen: 1, receipt: &g0.receipt, token: &g0.refresh };
    assert!(matches!(r2.begin(&q2), Err(RenewErr::Reject(Reject::Stale | Reject::Commitment))));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn runner_supervises_renews_and_tears_down() {
    let env = setup_with(4, Arc::new(MemStore::new()));
    let dir = std::env::temp_dir().join(format!("scout-run-{}", scout_wire::random_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let envfile = dir.join("env.txt");
    let mut c = Client::with_ureq(&env.srv.url());
    let o = scout_runner::Options {
        auto_consent: true,
        command: vec!["/bin/sh".into(), "-c".into(), format!("env > {}; sleep 4; exit 3", envfile.display())],
        renew_margin: 3,
        poll_every: std::time::Duration::from_millis(300),
        ..Default::default()
    };
    assert_eq!(scout_runner::run(&mut c, &o), 3);
    let envtxt = std::fs::read_to_string(&envfile).unwrap();
    let names: Vec<&str> = envtxt.lines().filter_map(|l| l.split('=').next()).collect();
    for n in &names {
        assert!(["PATH", "SCOUT_ACCESS_TOKEN", "PWD", "SHLVL", "_", "OLDPWD"].contains(n), "unexpected env var {n}");
    }
    assert!(names.contains(&"SCOUT_ACCESS_TOKEN"));
    assert!(family_calls(&env)[0] >= 1, "runner renewed");
    assert!(revocations(&env) >= 2);
    assert!(!env.store.dump().contains_key(&format!("sess/{}", c.session)), "finalized");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn runner_kills_the_process_group_when_the_session_is_revoked() {
    let env = setup();
    let mut c = Client::with_ureq(&env.srv.url());
    let store = env.store.clone();
    let o = scout_runner::Options {
        auto_consent: true,
        command: vec!["/bin/sh".into(), "-c".into(), "sleep 60 & wait".into()],
        poll_every: std::time::Duration::from_millis(200),
        kill_grace: std::time::Duration::from_secs(5),
        ..Default::default()
    };
    let t = std::thread::spawn(move || {
        // Wait for ACTIVE, then revoke the session behind the runner's back.
        for _ in 0..100 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let k = store.dump().keys().find(|k| k.starts_with("sess/")).cloned();
            if let Some(k) = k {
                let mut done = false;
                store
                    .update(&k, &mut |cur| {
                        let mut v: Value = serde_json::from_slice(cur?).ok()?;
                        if v["core"]["state"] != "Active" {
                            return None;
                        }
                        v["core"]["state"] = json!("Revoked");
                        done = true;
                        serde_json::to_vec(&v).ok()
                    })
                    .unwrap();
                if done {
                    return;
                }
            }
        }
    });
    let start = std::time::Instant::now();
    let code = scout_runner::run(&mut c, &o);
    t.join().unwrap();
    assert_eq!(code, 75);
    assert!(start.elapsed() < std::time::Duration::from_secs(20));
    assert!(!env.store.dump().contains_key(&format!("sess/{}", c.session)), "finalized");
}
