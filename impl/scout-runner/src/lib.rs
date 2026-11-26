// SPDX-License-Identifier: Apache-2.0

//! SCOUT runner: keys in memory only, signed requests, sealed grants opened in
//! memory, recoverable renewal, fail-closed supervision of one child command.
#![forbid(unsafe_code)]

use ed25519_dalek::SigningKey;
use scout_wire::http::{Transport, Ureq};
use scout_wire::proof::{self, Envelope};
use scout_wire::{b64, now_secs, random_bytes, seal, unb64};
use serde_json::{json, Value};
use std::sync::Arc;
use x25519_dalek::StaticSecret;

mod supervise;
pub use supervise::{run, Options};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallErr {
    /// No answer: the server may or may not have acted.
    Transport(String),
    Api(u16, String),
}

impl CallErr {
    pub fn code(&self) -> &str {
        match self {
            CallErr::Api(_, c) => c,
            CallErr::Transport(_) => "transport",
        }
    }
    /// Worth retrying with the same operation identifier.
    pub fn transient(&self) -> bool {
        matches!(self, CallErr::Transport(_) | CallErr::Api(502..=504, _)) || self.code() == "in_progress"
    }
}

impl std::fmt::Display for CallErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallErr::Transport(m) => write!(f, "transport: {m}"),
            CallErr::Api(s, c) => write!(f, "{s} {c}"),
        }
    }
}

type R<T> = Result<T, CallErr>;

#[derive(Clone, Debug)]
pub struct Grant {
    pub access: String,
    pub refresh: String,
    pub receipt: String,
    pub generation: u32,
    pub access_expires: u64,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub state: String,
    pub deadline: u64,
}

pub struct Client {
    pub base: String,
    pub authority: String,
    pub transport: Arc<dyn Transport>,
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    enc: StaticSecret,
    pub enc_pub: [u8; 32],
    sig: SigningKey,
    pub session: String,
    pub secret: String,
    pub grant_id: String,
    pub deadline: u64,
    pub capability: String,
}

impl Client {
    pub fn new(base: &str, transport: Arc<dyn Transport>) -> Client {
        let (enc, enc_pub) = seal::keypair();
        let authority = base.split("://").nth(1).unwrap_or(base).trim_end_matches('/').to_string();
        Client {
            base: base.trim_end_matches('/').to_string(),
            authority,
            transport,
            clock: Arc::new(now_secs),
            enc,
            enc_pub,
            sig: SigningKey::from_bytes(&random_bytes::<32>()),
            session: String::new(),
            secret: String::new(),
            grant_id: String::new(),
            deadline: 0,
            capability: "default".into(),
        }
    }

    pub fn with_ureq(base: &str) -> Client {
        Client::new(base, Arc::new(Ureq { redirects: 0 }))
    }

    pub fn sig_pub(&self) -> [u8; 32] {
        self.sig.verifying_key().to_bytes()
    }

    fn post(&self, path: &str, body: &Value) -> R<(u16, Vec<u8>)> {
        self.post_bytes(path, &serde_json::to_vec(body).unwrap_or_default())
    }

    fn post_bytes(&self, path: &str, body: &[u8]) -> R<(u16, Vec<u8>)> {
        let url = format!("{}{}", self.base, path);
        self.transport.call("POST", &url, &[("Content-Type", "application/json")], body).map_err(|e| CallErr::Transport(e.0))
    }

    fn ok(&self, path: &str, body: &Value) -> R<Value> {
        let (s, b) = self.post(path, body)?;
        parse_reply(s, &b)
    }

    /// Session-bound proof body plus request-specific fields.
    pub fn proof(&self, route: &str, extra: Value) -> Envelope {
        let mut body = json!({ "method": "POST", "route": route, "authority": self.authority, "session": self.session,
                               "signedAt": (self.clock)(), "nonce": scout_wire::random_id() });
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            b.extend(e.clone());
        }
        proof::sign(&self.sig, body)
    }

    pub fn route(&self, op: &str) -> String {
        format!("/v1/sessions/{}/{op}", self.session)
    }

    /// One-shot creation: the runner keys are pinned at creation.
    pub fn create(&mut self, ttl: u64) -> R<()> {
        let v = self.ok(
            "/v1/sessions",
            &json!({ "encPub": b64(&self.enc_pub), "sigPub": b64(&self.sig_pub()), "ttlSeconds": ttl, "capability": self.capability }),
        )?;
        self.adopt(&v);
        Ok(())
    }

    /// Split creation, first half (the requester): no keys yet.
    pub fn create_unbound(&mut self, ttl: u64) -> R<()> {
        let v = self.ok("/v1/sessions", &json!({ "ttlSeconds": ttl, "capability": self.capability }))?;
        self.adopt(&v);
        Ok(())
    }

    /// Split creation, second half (the runner): pin keys with the session secret.
    pub fn bind(&mut self, session: &str, secret: &str) -> R<()> {
        self.session = session.into();
        self.secret = secret.into();
        self.ok(&self.route("bind"), &json!({ "secret": secret, "encPub": b64(&self.enc_pub), "sigPub": b64(&self.sig_pub()) }))?;
        Ok(())
    }

    fn adopt(&mut self, v: &Value) {
        self.session = v["sessionId"].as_str().unwrap_or("").into();
        self.secret = v["sessionSecret"].as_str().unwrap_or("").into();
        self.grant_id = v["grantId"].as_str().unwrap_or("").into();
        self.deadline = v["deadline"].as_u64().unwrap_or(0);
    }

    pub fn consent_url(&self, principal: &str) -> String {
        format!("{}/v1/sessions/{}/consent?principal={}", self.base, self.session, scout_wire::http::urlencode(principal))
    }

    pub fn status(&self) -> R<Status> {
        let route = self.route("status");
        let v = self.ok(&route, &json!({ "proof": self.proof(&route, json!({})) }))?;
        Ok(Status { state: v["state"].as_str().unwrap_or("").into(), deadline: v["deadline"].as_u64().unwrap_or(0) })
    }

    /// Signs once and re-sends the identical bytes after an uncertain outcome:
    /// an earlier copy may still be executing, so a fresh proof would look like a different request.
    pub fn fetch_grant(&self) -> R<Grant> {
        let route = self.route("grant");
        let body = serde_json::to_vec(&json!({ "proof": self.proof(&route, json!({})) })).unwrap_or_default();
        let mut last = CallErr::Transport("no attempt".into());
        for _ in 0..3 {
            match self.post_bytes(&route, &body) {
                Ok((s, b)) => {
                    let v = parse_reply(s, &b)?;
                    return self.open_grant(&v, None);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    pub fn open_grant(&self, v: &Value, prev_refresh: Option<&str>) -> R<Grant> {
        let gen = u32::try_from(v["generation"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX);
        let grant = v["grant"].as_str().unwrap_or("");
        let open = |kind: &str, field: &Value| -> R<String> {
            let ct = unb64(field["sealed"].as_str().unwrap_or("")).map_err(|e| CallErr::Transport(e.0))?;
            let pt = seal::open(&ct, &self.enc, &seal::aad(&self.session, grant, kind, gen)).map_err(|e| CallErr::Transport(e.0))?;
            String::from_utf8(pt).map_err(|_| CallErr::Transport("token not utf-8".into()))
        };
        let refresh = match v.get("refresh") {
            Some(r) => open("refresh", r)?,
            None => prev_refresh.ok_or_else(|| CallErr::Transport("no refresh token".into()))?.to_string(),
        };
        Ok(Grant {
            access: open("access", &v["access"])?,
            refresh,
            receipt: v["receipt"].as_str().unwrap_or("").into(),
            generation: gen,
            access_expires: (self.clock)() + v["access"]["expiresIn"].as_u64().unwrap_or(0),
        })
    }

    /// One renewal attempt; returns the raw reply so callers can compare retries.
    pub fn renew_raw(&self, g: &Grant, op: &str) -> R<Vec<u8>> {
        let route = self.route("renew");
        let p = self.proof(
            &route,
            json!({ "capability": self.capability, "generation": g.generation, "receipt": g.receipt,
                    "refreshHash": scout_wire::commit::sha256_hex(g.refresh.as_bytes()), "operationId": op }),
        );
        let (s, b) = self.post(&route, &json!({ "proof": p, "refreshToken": g.refresh }))?;
        if s != 200 {
            parse_reply(s, &b)?;
        }
        Ok(b)
    }

    pub fn renew(&self, g: &Grant, op: &str) -> R<Grant> {
        let b = self.renew_raw(g, op)?;
        let v: Value = serde_json::from_slice(&b).map_err(|e| CallErr::Transport(e.to_string()))?;
        self.open_grant(&v, Some(&g.refresh))
    }

    /// Keeps the same operation identifier, token and receipt on every retry.
    pub fn renew_recoverable(&self, g: &Grant, attempts: u32, backoff: std::time::Duration) -> R<Grant> {
        let op = scout_wire::random_id();
        let mut last = CallErr::Transport("no attempt".into());
        for i in 0..attempts {
            match self.renew(g, &op) {
                Ok(n) => return Ok(n),
                Err(e) if e.transient() => last = e,
                Err(e) => return Err(e),
            }
            std::thread::sleep(backoff * (i + 1));
        }
        Err(last)
    }

    /// Per-token outcomes: (kind, outcome).
    pub fn revoke(&self, tokens: &[(&str, &str)]) -> R<Vec<(String, String)>> {
        let route = self.route("revoke");
        let hashes: Vec<String> = tokens.iter().map(|(_, t)| scout_wire::commit::sha256_hex(t.as_bytes())).collect();
        let list: Vec<Value> = tokens.iter().map(|(k, t)| json!({ "kind": k, "token": t })).collect();
        let v = self.ok(&route, &json!({ "proof": self.proof(&route, json!({ "tokenHashes": hashes })), "tokens": list }))?;
        Ok(v["outcomes"]
            .as_array()
            .map(|a| a.iter().map(|o| (o["kind"].as_str().unwrap_or("").into(), o["outcome"].as_str().unwrap_or("").into())).collect())
            .unwrap_or_default())
    }

    pub fn finalize(&self) -> R<()> {
        self.ok(&self.route("finalize"), &json!({ "secret": self.secret }))?;
        Ok(())
    }
}

fn parse_reply(status: u16, body: &[u8]) -> R<Value> {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if status == 200 {
        return Ok(v);
    }
    Err(CallErr::Api(status, v["error"].as_str().unwrap_or("error").to_string()))
}
