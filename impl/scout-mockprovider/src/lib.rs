// SPDX-License-Identifier: CC-BY-4.0

//! A small OAuth 2.0 provider for demos and tests: confidential client,
//! single-use rotating refresh tokens, RFC 7009 revocation, fault injection.
#![forbid(unsafe_code)]

use scout_wire::http::{self, Handler, Request, Response, Server};
use scout_wire::{now_secs, random_id};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub auto_approve: bool,
    pub access_ttl: u64,
}

struct Family {
    id: String,
    current: String,
    refresh_calls: u32,
    generation: u32,
    revoked: bool,
}

#[derive(Default)]
struct State {
    codes: HashMap<String, (String, String)>,
    fams: Vec<Family>,
    refresh_owner: HashMap<String, usize>,
    access: HashMap<String, (usize, u64, bool)>,
    drop_next: u32,
    dropped: u32,
    revocations: u32,
}

pub fn start(addr: &str, cfg: Config) -> std::io::Result<Server> {
    let cfg = Arc::new(cfg);
    let st = Arc::new(Mutex::new(State::default()));
    let h: Handler = Arc::new(move |r| route(&cfg, &st, r, None));
    http::serve(addr, h)
}

/// Two listeners over one state: the front one serves the browser and resource
/// routes (authorize, whoami, debug), the back one only the token and
/// revocation endpoints, so a network policy can admit different callers per port.
pub fn start_split(front: &str, back: &str, cfg: Config) -> std::io::Result<(Server, Server)> {
    let cfg = Arc::new(cfg);
    let st = Arc::new(Mutex::new(State::default()));
    let (c2, s2) = (cfg.clone(), st.clone());
    let f = http::serve(front, Arc::new(move |r| route(&cfg, &st, r, Some(false))))?;
    let b = http::serve(back, Arc::new(move |r| route(&c2, &s2, r, Some(true))))?;
    Ok((f, b))
}

fn oauth_err(status: u16, e: &str) -> Option<Response> {
    Some(Response::json(status, &json!({ "error": e })))
}

fn route(cfg: &Config, st: &Mutex<State>, r: Request, back: Option<bool>) -> Option<Response> {
    let mut s = st.lock().ok()?;
    let is_back_route = matches!(r.path.as_str(), "/token" | "/revoke");
    if back.is_some_and(|b| b != is_back_route) && r.path != "/healthz" {
        return Some(Response::text(404, "not found"));
    }
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/healthz") => Some(Response::text(200, "ok")),
        ("GET", "/authorize") => authorize(cfg, &mut s, &r),
        ("POST", "/token") => token(cfg, &mut s, &r),
        ("POST", "/revoke") => revoke(cfg, &mut s, &r),
        ("GET", "/api/whoami") => {
            let tok = r.headers.get("authorization").and_then(|h| h.strip_prefix("Bearer ")).unwrap_or("");
            match s.access.get(tok) {
                Some((fam, exp, false)) if *exp > now_secs() && !s.fams[*fam].revoked => {
                    Some(Response::json(200, &json!({ "sub": "demo-user", "family": s.fams[*fam].id })))
                }
                _ => oauth_err(401, "invalid_token"),
            }
        }
        ("POST", "/debug/fault") => {
            s.drop_next = r.query.get("drop_refresh").and_then(|v| v.parse().ok()).unwrap_or(0);
            Some(Response::text(200, "ok"))
        }
        ("GET", "/debug/stats") => {
            let fams: Vec<Value> = s
                .fams
                .iter()
                .map(|f| json!({ "id": f.id, "refreshCalls": f.refresh_calls, "generation": f.generation, "revoked": f.revoked }))
                .collect();
            Some(Response::json(200, &json!({ "families": fams, "revocations": s.revocations, "dropped": s.dropped })))
        }
        _ => Some(Response::text(404, "not found")),
    }
}

fn authorize(cfg: &Config, s: &mut State, r: &Request) -> Option<Response> {
    let q = &r.query;
    let (Some(cid), Some(redirect)) = (q.get("client_id"), q.get("redirect_uri")) else {
        return Some(Response::text(400, "missing client_id or redirect_uri"));
    };
    if cid != &cfg.client_id || q.get("response_type").map(String::as_str) != Some("code") {
        return Some(Response::text(400, "bad request"));
    }
    let state = http::urlencode(q.get("state").map(String::as_str).unwrap_or(""));
    if !cfg.auto_approve && q.get("approve").is_none() {
        return Some(Response::text(200, "append &approve=1 to this URL to approve (demo provider)"));
    }
    let code = random_id();
    s.codes.insert(code.clone(), (cid.clone(), redirect.clone()));
    let sep = if redirect.contains('?') { '&' } else { '?' };
    Some(Response::redirect(&format!("{redirect}{sep}code={code}&state={state}")))
}

fn issue(cfg: &Config, s: &mut State, fam: usize) -> Value {
    let access = format!("at_{}", random_id());
    let refresh = format!("rt_{}", random_id());
    s.access.insert(access.clone(), (fam, now_secs() + cfg.access_ttl, false));
    s.refresh_owner.insert(refresh.clone(), fam);
    let f = &mut s.fams[fam];
    f.current = refresh.clone();
    f.generation += 1;
    json!({ "access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": cfg.access_ttl })
}

fn client_ok(cfg: &Config, f: &HashMap<String, String>) -> bool {
    f.get("client_id") == Some(&cfg.client_id) && f.get("client_secret") == Some(&cfg.client_secret)
}

fn token(cfg: &Config, s: &mut State, r: &Request) -> Option<Response> {
    let f = http::parse_form(&String::from_utf8_lossy(&r.body));
    if !client_ok(cfg, &f) {
        return oauth_err(401, "invalid_client");
    }
    match f.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some((cid, redirect)) = f.get("code").and_then(|c| s.codes.remove(c)) else { return oauth_err(400, "invalid_grant") };
            if f.get("redirect_uri") != Some(&redirect) || f.get("client_id") != Some(&cid) {
                return oauth_err(400, "invalid_grant");
            }
            s.fams.push(Family {
                id: format!("fam-{}", s.fams.len() + 1),
                current: String::new(),
                refresh_calls: 0,
                generation: 0,
                revoked: false,
            });
            let fam = s.fams.len() - 1;
            Some(Response::json(200, &issue(cfg, s, fam)))
        }
        Some("refresh_token") => {
            let tok = f.get("refresh_token").cloned().unwrap_or_default();
            let Some(&fam) = s.refresh_owner.get(&tok) else { return oauth_err(400, "invalid_grant") };
            s.fams[fam].refresh_calls += 1;
            if s.fams[fam].revoked || s.fams[fam].current != tok {
                return oauth_err(400, "invalid_grant");
            }
            let body = issue(cfg, s, fam);
            if s.drop_next > 0 {
                // The rotation happened; the reply never arrives.
                s.drop_next -= 1;
                s.dropped += 1;
                return None;
            }
            Some(Response::json(200, &body))
        }
        _ => oauth_err(400, "unsupported_grant_type"),
    }
}

fn revoke(cfg: &Config, s: &mut State, r: &Request) -> Option<Response> {
    let f = http::parse_form(&String::from_utf8_lossy(&r.body));
    if !client_ok(cfg, &f) {
        return oauth_err(401, "invalid_client");
    }
    let tok = f.get("token").cloned().unwrap_or_default();
    s.revocations += 1;
    if let Some(&fam) = s.refresh_owner.get(&tok) {
        s.fams[fam].revoked = true;
    } else if let Some(a) = s.access.get_mut(&tok) {
        a.2 = true;
    }
    Some(Response::text(200, ""))
}
