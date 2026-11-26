// SPDX-License-Identifier: Apache-2.0

//! Recoverable renewal as plain functions over the store, with an injectable
//! clock. Every decision is made by `scout_core::renewal::step`; this file maps
//! real byte strings to the opaque ids the core works with.
use crate::provider::{ProvErr, Refresher, Tokens};
use crate::records::{ctl_key, parse, to_bytes, Control};
use crate::store::Store;
use scout_core::renewal::{self, Ev, Out, Vol};
use scout_core::Reject;
use scout_wire::commit::{self, ReceiptInput};
use scout_wire::{b64, seal, unb64, Error};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, PartialEq, Eq)]
pub enum RenewErr {
    Reject(Reject),
    NotFound,
    Provider(String),
    Internal(String),
}

impl From<Error> for RenewErr {
    fn from(e: Error) -> Self {
        RenewErr::Internal(e.0)
    }
}

pub struct BeginReq<'a> {
    pub session: &'a str,
    pub op: &'a str,
    pub gen: u32,
    pub receipt: &'a str,
    pub token: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub op: String,
    pub gen: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BeginOut {
    Reserved(Claim),
    Replay(Vec<u8>),
}

pub struct Renewer {
    pub store: Arc<dyn Store>,
    pub key: Vec<u8>,
    pub provider_ref: String,
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Volatile bookkeeping a crash loses.
    vols: Mutex<HashMap<String, Vol>>,
}

pub struct NewControl<'a> {
    pub session: &'a str,
    pub grant: &'a str,
    pub capability: &'a str,
    pub enc_pub: [u8; 32],
    pub sig_pub: [u8; 32],
    pub deadline: u64,
}

fn seal_reply(
    key: &[u8],
    c: &Control,
    session: &str,
    gen: u32,
    commitment: &[u8],
    t: &Tokens,
    refresh: Option<&str>,
) -> Result<(Vec<u8>, String), Error> {
    let enc: [u8; 32] = unb64(&c.enc_pub)?.try_into().map_err(|_| Error("enc key".into()))?;
    let sig = unb64(&c.sig_pub)?;
    let receipt = commit::receipt(
        key,
        &ReceiptInput { session, grant: &c.grant_id, generation: gen, commitment, enc_pub: &enc, sig_pub: &sig, policy: &c.capability },
    );
    let access = seal::seal(t.access.as_bytes(), &enc, &seal::aad(session, &c.grant_id, "access", gen))?;
    let mut reply = json!({
        "session": session, "grant": c.grant_id, "capability": c.capability, "generation": gen,
        "receipt": receipt, "access": { "sealed": b64(&access), "expiresIn": t.expires_in },
    });
    if let Some(r) = refresh {
        let rs = seal::seal(r.as_bytes(), &enc, &seal::aad(session, &c.grant_id, "refresh", gen))?;
        reply["refresh"] = json!({ "sealed": b64(&rs) });
    }
    Ok((to_bytes(&reply), receipt))
}

impl Renewer {
    pub fn new(store: Arc<dyn Store>, key: Vec<u8>, provider_ref: &str, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Renewer {
        Renewer { store, key, provider_ref: provider_ref.to_string(), clock, vols: Mutex::new(HashMap::new()) }
    }

    /// A renewer over another store and clock that inherits the volatile bookkeeping (model checking).
    pub fn fork(&self, store: Arc<dyn Store>, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Renewer {
        let vols = self.vols.lock().map(|m| m.clone()).unwrap_or_default();
        Renewer { store, key: self.key.clone(), provider_ref: self.provider_ref.clone(), clock, vols: Mutex::new(vols) }
    }

    /// Volatile bookkeeping, for state deduplication.
    pub fn volatile(&self) -> Vec<(String, Vol)> {
        let mut v: Vec<_> = self.vols.lock().map(|m| m.iter().map(|(k, v)| (k.clone(), *v)).collect()).unwrap_or_default();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    fn set_vol(&self, session: &str, v: Vol) {
        if let Ok(mut m) = self.vols.lock() {
            m.insert(session.to_string(), v);
        }
    }

    fn vol(&self, session: &str) -> Vol {
        self.vols.lock().ok().and_then(|m| m.get(session).copied()).unwrap_or_default()
    }

    /// Creates the control record at the original consent exchange (and never
    /// afterwards) and returns the sealed first grant.
    pub fn init_control(&self, n: &NewControl, t: &Tokens) -> Result<Vec<u8>, RenewErr> {
        let refresh = t.refresh.as_deref().ok_or_else(|| RenewErr::Internal("provider returned no refresh token".into()))?;
        let commitment = commit::commitment(&self.key, n.grant, &self.provider_ref, 0, refresh);
        let mut c = Control::closed_marker();
        c.ctl = renewal::Ctl::new(n.deadline, 1);
        c.del = scout_core::delivery::Del::new();
        c.td = scout_core::teardown::Td::new();
        c.grant_id = n.grant.to_string();
        c.capability = n.capability.to_string();
        c.enc_pub = b64(&n.enc_pub);
        c.sig_pub = b64(&n.sig_pub);
        c.commit = b64(&commitment);
        let (grant, receipt) = seal_reply(&self.key, &c, n.session, 0, &commitment, t, Some(refresh))?;
        c.receipt = receipt;
        c.initial_grant = b64(&grant);
        c.digests = vec![commit::token_digest(&self.key, n.session, &t.access), commit::token_digest(&self.key, n.session, refresh)];
        let mut created = false;
        self.store
            .update(&ctl_key(n.session), &mut |cur| {
                if cur.is_some() {
                    return None;
                }
                created = true;
                Some(to_bytes(&c))
            })
            .map_err(RenewErr::from)?;
        if !created {
            return Err(RenewErr::Reject(Reject::State));
        }
        Ok(grant)
    }

    /// Admission: one conditional write that checks the commitment and reserves
    /// the generation for one operation, or returns the saved reply.
    pub fn begin(&self, q: &BeginReq) -> Result<BeginOut, RenewErr> {
        let now = (self.clock)();
        let mut result = Err(RenewErr::NotFound);
        let key = ctl_key(q.session);
        let mut prior_vol = None;
        self.store
            .update(&key, &mut |cur| {
                let raw = cur?;
                let mut c: Control = parse(raw)?;
                prior_vol = Some(self.vol(q.session));
                c.ctl.vol = self.vol(q.session);
                if let Ok((n, _)) = renewal::step(&c.ctl, Ev::Retire { now }) {
                    if n.saved.reply == 0 && c.ctl.saved.reply != 0 {
                        c.saved_reply.clear();
                        c.saved_op.clear();
                    }
                    c.ctl = n;
                }
                // The receipt of the committed generation, or of the one a saved reply replaces.
                let receipt_ok = !c.receipt.is_empty()
                    && (commit::ct_eq(q.receipt.as_bytes(), c.receipt.as_bytes())
                        || (!c.prev_receipt.is_empty() && commit::ct_eq(q.receipt.as_bytes(), c.prev_receipt.as_bytes())));
                let mac = |gen: u32| commit::commitment(&self.key, &c.grant_id, &self.provider_ref, gen, q.token);
                let cur_ok = unb64(&c.commit).map(|x| commit::ct_eq(&mac(q.gen), &x)).unwrap_or(false);
                let prev_ok = unb64(&c.prev_commit).map(|x| !x.is_empty() && commit::ct_eq(&mac(q.gen), &x)).unwrap_or(false);
                // Operation ids: a string that names the stored claim or saved reply gets that id.
                let op = if !c.claim_op.is_empty() && c.claim_op == q.op {
                    c.ctl.claim_op
                } else if !c.saved_op.is_empty() && c.saved_op == q.op {
                    c.ctl.saved.op
                } else {
                    c.next_id
                };
                if !receipt_ok && c.ctl.phase != renewal::Phase::Closed {
                    result = Err(RenewErr::Reject(Reject::Commitment));
                    return None;
                }
                let ev = Ev::Begin { op, gen: q.gen, now, cur_ok, prev_ok };
                match renewal::step(&c.ctl, ev) {
                    Err(r) => {
                        result = Err(RenewErr::Reject(r));
                        None
                    }
                    Ok((n, out)) => {
                        c.ctl = n;
                        match out {
                            Out::Reserved => {
                                c.claim_op = q.op.to_string();
                                c.next_id += 1;
                                c.saved_op.clear();
                                c.saved_reply.clear();
                                c.prev_commit.clear();
                                c.prev_receipt.clear();
                                result = Ok(BeginOut::Reserved(Claim { op: q.op.to_string(), gen: q.gen }));
                            }
                            Out::Replay(_) => {
                                result = unb64(&c.saved_reply).map(BeginOut::Replay).map_err(RenewErr::from);
                            }
                            _ => result = Err(RenewErr::Reject(Reject::Recovery)),
                        }
                        self.set_vol(q.session, n.vol);
                        Some(to_bytes(&c))
                    }
                }
            })
            .map_err(RenewErr::from)?;
        if let Err(RenewErr::Internal(_)) = &result {
            self.set_vol(q.session, prior_vol.unwrap_or_default());
        }
        result
    }

    /// Permission to use the client authentication for the reserved generation.
    pub fn permit_exchange(&self, session: &str) -> Result<(), RenewErr> {
        let mut r = Err(RenewErr::NotFound);
        self.store
            .update(&ctl_key(session), &mut |cur| {
                let mut c: Control = parse(cur?)?;
                c.ctl.vol = self.vol(session);
                r = match renewal::step(&c.ctl, Ev::Exchange) {
                    Ok((n, _)) => {
                        self.set_vol(session, n.vol);
                        Ok(())
                    }
                    Err(e) => Err(RenewErr::Reject(e)),
                };
                None
            })
            .map_err(RenewErr::from)?;
        r
    }

    /// The single conditional write: sealed reply, next commitment and next
    /// generation are stored together or not at all.
    pub fn commit(&self, session: &str, claim: &Claim, t: &Tokens, presented: &str) -> Result<Vec<u8>, RenewErr> {
        let now = (self.clock)();
        let mut r = Err(RenewErr::NotFound);
        self.store
            .update(&ctl_key(session), &mut |cur| {
                let mut c: Control = parse(cur?)?;
                c.ctl.vol = self.vol(session);
                let op = if c.claim_op == claim.op { c.ctl.claim_op } else { 0 };
                let gen = c.ctl.gen + 1;
                let refresh = t.refresh.as_deref().unwrap_or(presented);
                let next = commit::commitment(&self.key, &c.grant_id, &self.provider_ref, gen, refresh);
                let ev = Ev::Commit { op, reply: gen, next_commit: gen, now };
                let n = match renewal::step(&c.ctl, ev) {
                    Ok((n, _)) => n,
                    Err(e) => {
                        r = Err(RenewErr::Reject(e));
                        return None;
                    }
                };
                let sealed = seal_reply(&self.key, &c, session, gen, &next, t, t.refresh.as_deref());
                let (reply, receipt) = match sealed {
                    Ok(x) => x,
                    Err(e) => {
                        r = Err(e.into());
                        return None;
                    }
                };
                c.prev_commit = std::mem::replace(&mut c.commit, b64(&next));
                c.prev_receipt = std::mem::replace(&mut c.receipt, receipt);
                c.saved_op = std::mem::take(&mut c.claim_op);
                c.saved_reply = b64(&reply);
                c.digests.push(commit::token_digest(&self.key, session, &t.access));
                if let Some(rt) = &t.refresh {
                    c.digests.push(commit::token_digest(&self.key, session, rt));
                }
                c.ctl = n;
                self.set_vol(session, n.vol);
                r = Ok(reply);
                Some(to_bytes(&c))
            })
            .map_err(RenewErr::from)?;
        r
    }

    /// Volatile state is lost; the reservation in the store is not released.
    pub fn crash(&self, session: &str) {
        if let Ok(mut m) = self.vols.lock() {
            m.remove(session);
        }
    }

    /// Closure of the shared record.
    pub fn close(&self, session: &str) -> Result<(), RenewErr> {
        self.store
            .update(&ctl_key(session), &mut |cur| {
                let mut c = cur.and_then(parse::<Control>).unwrap_or_else(Control::closed_marker);
                c.close();
                Some(to_bytes(&c))
            })
            .map_err(RenewErr::from)?;
        self.crash(session);
        Ok(())
    }

    /// Admission, one provider exchange and the single commit.
    pub fn renew(&self, q: &BeginReq, provider: &dyn Refresher) -> Result<Vec<u8>, RenewErr> {
        let claim = match self.begin(q)? {
            BeginOut::Replay(r) => return Ok(r),
            BeginOut::Reserved(c) => c,
        };
        let fail = |e: RenewErr| {
            // The reservation stays: only this worker's memory is dropped.
            self.crash(q.session);
            e
        };
        self.permit_exchange(q.session).map_err(fail)?;
        let tokens = provider.refresh(q.token).map_err(|e| {
            fail(RenewErr::Provider(match e {
                ProvErr::Rejected(s) => format!("provider answered {s}"),
                ProvErr::Unknown(m) => m,
            }))
        })?;
        match self.commit(q.session, &claim, &tokens, q.token) {
            Ok(r) => Ok(r),
            Err(e) => {
                provider.discard(&tokens);
                Err(fail(e))
            }
        }
    }
}
