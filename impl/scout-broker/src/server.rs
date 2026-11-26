// SPDX-License-Identifier: CC-BY-4.0

//! HTTP handlers. Token values are never logged; the access log has method,
//! path (no query) and status only.
use crate::provider::Provider;
use crate::records::{ctl_key, parse, sess_key, to_bytes, Control, SessionRec};
use crate::renewal::{BeginReq, NewControl, RenewErr, Renewer};
use crate::store::Store;
use scout_core::session::{self, Ev as SEv, Sess, St};
use scout_core::teardown::{self, Ev as TEv, Reported};
use scout_core::{delivery, Reject};
use scout_wire::commit::{self};
use scout_wire::http::{Handler, Request, Response};
use scout_wire::proof::Envelope;
use scout_wire::{b64, hex, random_id, unb64};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct Config {
    /// Host[:port] the runner signs into every proof.
    pub authority: String,
    /// Externally visible base URL (used for the OAuth redirect URI).
    pub public_base: String,
    pub default_ttl: u64,
    pub max_ttl: u64,
}

pub struct Broker {
    pub cfg: Config,
    pub store: Arc<dyn Store>,
    pub renewer: Renewer,
    pub provider: Provider,
}

type ApiErr = (u16, String);
type Api<T> = Result<T, ApiErr>;

fn err(status: u16, code: &str) -> ApiErr {
    (status, code.to_string())
}

fn reject(r: Reject) -> ApiErr {
    let (s, c) = match r {
        Reject::State => (409, "bad_state"),
        Reject::NotBound => (409, "bind_required"),
        Reject::Principal => (403, "principal_locked"),
        Reject::Key => (409, "key_mismatch"),
        Reject::Blocked => (409, "delivery_blocked"),
        Reject::Closed => (410, "closed"),
        Reject::Recovery => (409, "recovery_required"),
        Reject::Stale => (409, "stale_generation"),
        Reject::Commitment => (403, "commitment_mismatch"),
        Reject::Competing => (409, "competing_operation"),
        Reject::InProgress => (409, "in_progress"),
        Reject::Expired => (410, "expired"),
        Reject::Lapsed => (410, "reply_lapsed"),
        Reject::NoClaim => (409, "no_claim"),
        Reject::NotDelivered => (403, "not_delivered"),
        Reject::NoKey => (409, "no_key"),
        Reject::NotClosed => (409, "not_closed"),
    };
    err(s, c)
}

fn renew_err(e: RenewErr) -> ApiErr {
    match e {
        RenewErr::Reject(r) => reject(r),
        RenewErr::NotFound => err(404, "not_found"),
        RenewErr::Provider(_) => err(502, "provider_unavailable"),
        RenewErr::Internal(_) => err(500, "internal"),
    }
}

fn internal<E>(_: E) -> ApiErr {
    err(500, "internal")
}

pub fn state_name(s: St) -> &'static str {
    match s {
        St::Pending => "PENDING",
        St::Bound => "BOUND",
        St::Authorized => "AUTHORIZED",
        St::Active => "ACTIVE",
        St::Denied => "DENIED",
        St::Revoked => "REVOKED",
        St::Expired => "EXPIRED",
    }
}

fn outcome_name(r: Reported) -> &'static str {
    match r {
        Reported::Revoked => "acknowledged",
        Reported::Unsupported => "unsupported",
        Reported::Failed => "failed",
        Reported::Unknown => "unknown",
    }
}

fn json_body(r: &Request) -> Api<Value> {
    serde_json::from_slice(&r.body).map_err(|_| err(400, "bad_json"))
}

impl Broker {
    pub fn handler(self: &Arc<Self>) -> Handler {
        let b = self.clone();
        Arc::new(move |r| {
            let (m, p) = (r.method.clone(), r.path.clone());
            let resp = match b.route(r) {
                Ok(r) => r,
                Err((s, code)) => Response::json(s, &json!({ "error": code })),
            };
            eprintln!("{m} {p} {}", resp.status);
            Some(resp)
        })
    }

    fn now(&self) -> u64 {
        (self.renewer.clock)()
    }

    fn route(&self, r: Request) -> Api<Response> {
        let seg: Vec<&str> = r.path.trim_matches('/').split('/').collect();
        match (r.method.as_str(), seg.as_slice()) {
            ("GET", ["healthz"]) => Ok(Response::text(200, "ok")),
            ("GET", ["callback"]) => self.callback(&r),
            ("POST", ["v1", "sessions"]) => self.create(&r),
            (_, ["v1", "sessions", id, op]) => {
                let id = *id;
                match (r.method.as_str(), *op) {
                    ("POST", "bind") => self.bind(&r, id),
                    ("GET", "consent") => self.consent(&r, id),
                    ("POST", "grant") => self.grant(&r, id),
                    ("POST", "renew") => self.renew(&r, id),
                    ("POST", "revoke") => self.revoke(&r, id),
                    ("POST", "finalize") => self.finalize(&r, id),
                    ("POST", "status") => self.status(&r, id),
                    _ => Err(err(404, "not_found")),
                }
            }
            _ => Err(err(404, "not_found")),
        }
    }

    // ---- session records ----

    /// Applies expiry, then `f` to a copy; `f`'s changes persist only if it succeeds.
    fn mutate(&self, id: &str, f: impl FnOnce(&mut SessionRec) -> Result<(), ApiErr>) -> Api<SessionRec> {
        let now = self.now();
        let mut out: Api<SessionRec> = Err(err(404, "not_found"));
        let mut f = Some(f);
        self.store
            .update(&sess_key(id), &mut |cur| {
                let raw = cur?;
                let mut s: SessionRec = parse(raw)?;
                if let Ok(n) = session::step(&s.core, SEv::Tick { now }) {
                    s.core = n;
                }
                let mut copy = s.clone();
                match f.take().map(|f| f(&mut copy)).unwrap_or(Ok(())) {
                    Ok(()) => {
                        s = copy;
                        out = Ok(s.clone());
                    }
                    Err(e) => out = Err(e),
                }
                let next = to_bytes(&s);
                (next != raw).then_some(next)
            })
            .map_err(internal)?;
        out
    }

    fn load(&self, id: &str) -> Api<SessionRec> {
        match self.mutate(id, |_| Ok(())) {
            Err((404, _)) => match self.store.get(&ctl_key(id)).map_err(internal)?.and_then(|b| parse::<Control>(&b)) {
                Some(c) if c.ctl.phase == scout_core::renewal::Phase::Closed => Err(err(410, "closed")),
                _ => Err(err(404, "not_found")),
            },
            other => other,
        }
    }

    fn step(&self, s: &mut SessionRec, e: SEv) -> Result<(), ApiErr> {
        s.core = session::step(&s.core, e).map_err(reject)?;
        Ok(())
    }

    fn pubkey(s: &str) -> Api<[u8; 32]> {
        unb64(s).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| err(400, "bad_key"))
    }

    // ---- creation and binding ----

    fn create(&self, r: &Request) -> Api<Response> {
        let v = json_body(r)?;
        let id = random_id();
        let secret = b64(&scout_wire::random_bytes::<32>());
        let ttl = v["ttlSeconds"].as_u64().unwrap_or(self.cfg.default_ttl).min(self.cfg.max_ttl);
        let mut rec = SessionRec {
            id: id.clone(),
            grant_id: random_id(),
            capability: v["capability"].as_str().unwrap_or("default").to_string(),
            secret_hash: b64(&commit::secret_hash(&secret)),
            enc_pub: String::new(),
            sig_pub: String::new(),
            principal: String::new(),
            consent_state: String::new(),
            core: Sess::new(self.now() + ttl),
        };
        if v.get("encPub").is_some() || v.get("sigPub").is_some() {
            Self::pubkey(v["encPub"].as_str().unwrap_or(""))?;
            Self::pubkey(v["sigPub"].as_str().unwrap_or(""))?;
            rec.enc_pub = v["encPub"].as_str().unwrap_or("").to_string();
            rec.sig_pub = v["sigPub"].as_str().unwrap_or("").to_string();
            self.step(&mut rec, SEv::Bind { key: 1 })?;
        }
        self.store.update(&sess_key(&id), &mut |_| Some(to_bytes(&rec))).map_err(internal)?;
        Ok(Response::json(
            200,
            &json!({ "sessionId": id, "sessionSecret": secret, "grantId": rec.grant_id, "state": state_name(rec.core.state),
                     "deadline": rec.core.deadline, "consentUrl": format!("{}/v1/sessions/{}/consent", self.cfg.public_base, id) }),
        ))
    }

    fn bind(&self, r: &Request, id: &str) -> Api<Response> {
        let v = json_body(r)?;
        let (enc, sig) = (v["encPub"].as_str().unwrap_or(""), v["sigPub"].as_str().unwrap_or(""));
        Self::pubkey(enc)?;
        Self::pubkey(sig)?;
        let secret = v["secret"].as_str().unwrap_or("");
        let s = self.mutate(id, |s| {
            let want = unb64(&s.secret_hash).unwrap_or_default();
            if !commit::ct_eq(&commit::secret_hash(secret), &want) {
                return Err(err(403, "bad_secret"));
            }
            self.step(s, SEv::Bind { key: 1 })?;
            s.enc_pub = enc.to_string();
            s.sig_pub = sig.to_string();
            Ok(())
        })?;
        Ok(Response::json(200, &json!({ "state": state_name(s.core.state) })))
    }

    // ---- consent ----

    fn consent(&self, r: &Request, id: &str) -> Api<Response> {
        let principal = r.query.get("principal").cloned().unwrap_or_default();
        if principal.is_empty() {
            return Err(err(400, "principal_required"));
        }
        let state = format!("{id}.{}", random_id());
        self.mutate(id, |s| {
            let pid = if s.principal.is_empty() || s.principal == principal { 1 } else { 2 };
            self.step(s, SEv::Consent { principal: pid })?;
            s.principal = principal.clone();
            s.consent_state = state.clone();
            Ok(())
        })?;
        Ok(Response::redirect(&self.provider.authorize_url(&format!("{}/callback", self.cfg.public_base), &state)))
    }

    fn callback(&self, r: &Request) -> Api<Response> {
        let state = r.query.get("state").cloned().unwrap_or_default();
        let id = state.split('.').next().unwrap_or("").to_string();
        let denied = r.query.contains_key("error");
        let rec = self.mutate(&id, |s| {
            if s.consent_state.is_empty() || !commit::ct_eq(s.consent_state.as_bytes(), state.as_bytes()) {
                return Err(err(400, "bad_state"));
            }
            s.consent_state.clear();
            if denied {
                self.step(s, SEv::Deny)?;
            }
            Ok(())
        })?;
        if denied {
            return Ok(Response::text(200, "authorization denied"));
        }
        let code = r.query.get("code").ok_or_else(|| err(400, "no_code"))?;
        let tokens = self
            .provider
            .exchange_code(code, &format!("{}/callback", self.cfg.public_base))
            .map_err(|_| err(502, "provider_unavailable"))?;
        let nc = NewControl {
            session: &id,
            grant: &rec.grant_id,
            capability: &rec.capability,
            enc_pub: Self::pubkey(&rec.enc_pub).unwrap_or([0; 32]),
            sig_pub: Self::pubkey(&rec.sig_pub).unwrap_or([0; 32]),
            deadline: rec.core.deadline,
        };
        let sealed_to_pinned = unb64(&rec.enc_pub).map(|b| b == nc.enc_pub).unwrap_or(false);
        let undo = |e: ApiErr| {
            // Nothing was delivered: do not leave the freshly minted tokens alive.
            self.provider.discard_tokens(&tokens);
            self.store.delete(&ctl_key(&id)).ok();
            e
        };
        self.renewer.init_control(&nc, &tokens).map_err(|e| undo(renew_err(e)))?;
        if let Err(e) = self.mutate(&id, |s| self.step(s, SEv::Authorize { seal_key: if sealed_to_pinned { 1 } else { 2 } })) {
            return Err(undo(e));
        }
        Ok(Response::text(200, "authorization complete; return to the runner"))
    }

    // ---- signed requests ----

    fn signed(&self, r: &Request, id: &str, body: &Value) -> Api<(Envelope, SessionRec)> {
        let env: Envelope = serde_json::from_value(body["proof"].clone()).map_err(|_| err(400, "bad_proof"))?;
        let s = self.load(id)?;
        if s.sig_pub.is_empty() {
            return Err(reject(Reject::NotBound));
        }
        env.verify(&unb64(&s.sig_pub).map_err(internal)?, self.now()).map_err(|_| err(401, "bad_proof"))?;
        if env.str("method") != r.method
            || env.str("route") != r.path
            || env.str("authority") != self.cfg.authority
            || env.str("session") != id
        {
            return Err(err(401, "proof_not_bound"));
        }
        Ok((env, s))
    }

    fn status(&self, r: &Request, id: &str) -> Api<Response> {
        let (_, s) = self.signed(r, id, &json_body(r)?)?;
        Ok(Response::json(200, &json!({ "state": state_name(s.core.state), "deadline": s.core.deadline, "now": self.now() })))
    }

    fn grant(&self, r: &Request, id: &str) -> Api<Response> {
        let (env, s) = self.signed(r, id, &json_body(r)?)?;
        if !session::deliverable(&s.core) {
            return Err(reject(Reject::State));
        }
        let digest = hex(&env.digest());
        let mut out: Api<delivery::Out> = Err(err(404, "not_found"));
        let mut resp = Vec::new();
        self.store
            .update(&ctl_key(id), &mut |cur| {
                let mut c: Control = parse(cur?)?;
                let ev = delivery::Ev::Fetch { same: !c.delivery_req.is_empty() && c.delivery_req == digest, resp: 1 };
                match delivery::step(&c.del, ev) {
                    Err(e) => {
                        out = Err(reject(e));
                        None
                    }
                    Ok((n, o)) => {
                        if c.ctl.phase == scout_core::renewal::Phase::Closed {
                            out = Err(reject(Reject::Closed));
                            return None;
                        }
                        match o {
                            delivery::Out::Release(_) => {
                                if c.delivery_req.is_empty() {
                                    c.delivery_req = digest.clone();
                                }
                                resp = unb64(&c.initial_grant).unwrap_or_default();
                            }
                            _ => c.initial_grant.clear(),
                        }
                        c.del = n;
                        out = Ok(o);
                        Some(to_bytes(&c))
                    }
                }
            })
            .map_err(internal)?;
        match out? {
            delivery::Out::Release(_) => {
                self.mutate(id, |s| if s.core.state == St::Authorized { self.step(s, SEv::Deliver) } else { Ok(()) })?;
                Ok(Response::raw_json(200, resp))
            }
            _ => {
                self.mutate(id, |s| self.step(s, SEv::Revoke)).ok();
                Err(err(409, "delivery_conflict"))
            }
        }
    }

    fn renew(&self, r: &Request, id: &str) -> Api<Response> {
        let body = json_body(r)?;
        let (env, s) = self.signed(r, id, &body)?;
        if !session::renewable(&s.core) {
            return Err(reject(Reject::State));
        }
        let token = body["refreshToken"].as_str().unwrap_or("");
        if env.str("capability") != s.capability
            || env.str("refreshHash") != commit::sha256_hex(token.as_bytes())
            || env.str("operationId").is_empty()
        {
            return Err(err(401, "proof_not_bound"));
        }
        let q = BeginReq {
            session: id,
            op: env.str("operationId"),
            gen: u32::try_from(env.u64("generation").unwrap_or(u64::MAX)).unwrap_or(u32::MAX),
            receipt: env.str("receipt"),
            token,
        };
        let reply = self.renewer.renew(&q, &self.provider).map_err(renew_err)?;
        Ok(Response::raw_json(200, reply))
    }

    fn revoke(&self, r: &Request, id: &str) -> Api<Response> {
        let body = json_body(r)?;
        let (env, _) = self.signed(r, id, &body)?;
        let toks: Vec<(String, String)> = body["tokens"]
            .as_array()
            .map(|a| {
                a.iter().map(|t| (t["kind"].as_str().unwrap_or("").to_string(), t["token"].as_str().unwrap_or("").to_string())).collect()
            })
            .unwrap_or_default();
        let hashes: Vec<String> = toks.iter().map(|(_, t)| commit::sha256_hex(t.as_bytes())).collect();
        if env.body["tokenHashes"] != json!(hashes) {
            return Err(err(401, "proof_not_bound"));
        }
        let c: Control = self.store.get(&ctl_key(id)).map_err(internal)?.and_then(|b| parse(&b)).ok_or_else(|| err(404, "not_found"))?;
        // Gate every token before any provider call.
        for (_, t) in &toks {
            let delivered = c.digests.contains(&commit::token_digest(&self.renewer.key, id, t));
            teardown::step(&c.td, TEv::Gate { delivered }).map_err(reject)?;
        }
        let out: Vec<Value> = toks
            .iter()
            .map(|(kind, t)| {
                let hint = if kind == "refresh" { "refresh_token" } else { "access_token" };
                let rep = teardown::classify(self.provider.revoke(t, hint));
                json!({ "kind": kind, "outcome": outcome_name(rep), "revoked": rep == Reported::Revoked })
            })
            .collect();
        self.mutate(id, |s| self.step(s, SEv::Revoke)).ok();
        Ok(Response::json(200, &json!({ "outcomes": out })))
    }

    fn finalize(&self, r: &Request, id: &str) -> Api<Response> {
        let v = json_body(r)?;
        let secret = v["secret"].as_str().unwrap_or("");
        let s: SessionRec = match self.store.get(&sess_key(id)).map_err(internal)?.and_then(|b| parse(&b)) {
            Some(s) => s,
            None => {
                return match self.store.get(&ctl_key(id)).map_err(internal)?.and_then(|b| parse::<Control>(&b)) {
                    Some(c) if c.td.closed => Ok(Response::json(200, &json!({ "closed": true }))),
                    _ => Err(err(404, "not_found")),
                }
            }
        };
        if !commit::ct_eq(&commit::secret_hash(secret), &unb64(&s.secret_hash).unwrap_or_default()) {
            return Err(err(403, "bad_secret"));
        }
        // Close first, then delete: closure is committed before any record or key goes away.
        self.renewer.close(id).map_err(renew_err)?;
        let mut res = Ok(());
        self.store
            .update(&ctl_key(id), &mut |cur| {
                let mut c: Control = parse(cur?)?;
                match teardown::step(&c.td, TEv::Delete) {
                    Ok((n, _)) => c.td = n,
                    Err(e) => {
                        res = Err(reject(e));
                        return None;
                    }
                }
                Some(to_bytes(&c))
            })
            .map_err(internal)?;
        res?;
        self.store.delete(&sess_key(id)).map_err(internal)?;
        Ok(Response::json(200, &json!({ "closed": true })))
    }
}

impl Provider {
    pub fn discard_tokens(&self, t: &crate::provider::Tokens) {
        use crate::provider::Refresher;
        self.discard(t);
    }
}
