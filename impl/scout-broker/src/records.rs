// SPDX-License-Identifier: CC-BY-4.0

//! Stored records. Protocol state lives in the `scout-core` types; the byte
//! strings those opaque ids stand for live beside them.
use scout_core::delivery::{self, Del};
use scout_core::renewal::{self, Ctl, Saved, Vol};
use scout_core::session::{Sess, St};
use scout_core::teardown::Td;
use scout_core::Id;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(remote = "St")]
enum StDef {
    Pending,
    Bound,
    Authorized,
    Active,
    Denied,
    Revoked,
    Expired,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Sess")]
struct SessDef {
    #[serde(with = "StDef")]
    state: St,
    deadline: u64,
    key: Id,
    principal: Id,
    minted: bool,
    sealed_to: Id,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "delivery::Phase")]
enum DPhaseDef {
    Fresh,
    Committed,
    Blocked,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Del")]
struct DelDef {
    #[serde(with = "DPhaseDef")]
    phase: delivery::Phase,
    resp: Id,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "renewal::Phase")]
enum RPhaseDef {
    Active,
    Refreshing,
    Ready,
    Recovery,
    Closed,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Saved")]
struct SavedDef {
    op: Id,
    reply: Id,
    until: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Vol")]
struct VolDef {
    inflight: bool,
    exchanged: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Ctl")]
struct CtlDef {
    #[serde(with = "RPhaseDef")]
    phase: renewal::Phase,
    gen: u32,
    deadline: u64,
    commit: Id,
    claim_op: Id,
    #[serde(with = "SavedDef")]
    saved: Saved,
    #[serde(with = "VolDef")]
    vol: Vol,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "Td")]
struct TdDef {
    key: bool,
    closed: bool,
    deleted: bool,
}

pub fn sess_key(id: &str) -> String {
    format!("sess/{id}")
}

pub fn ctl_key(id: &str) -> String {
    format!("ctl/{id}")
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionRec {
    pub id: String,
    pub grant_id: String,
    pub capability: String,
    /// Domain-separated SHA-256 of the session secret, base64.
    pub secret_hash: String,
    pub enc_pub: String,
    pub sig_pub: String,
    pub principal: String,
    pub consent_state: String,
    #[serde(with = "SessDef")]
    pub core: Sess,
}

/// The shared delivery-and-renewal record, one conditional-write unit.
#[derive(Serialize, Deserialize, Clone)]
pub struct Control {
    pub grant_id: String,
    pub capability: String,
    pub enc_pub: String,
    pub sig_pub: String,
    #[serde(with = "CtlDef")]
    pub ctl: Ctl,
    #[serde(with = "DelDef")]
    pub del: Del,
    #[serde(with = "TdDef")]
    pub td: Td,
    /// Commitment to the current refresh token, and to the one before it.
    pub commit: String,
    pub prev_commit: String,
    pub receipt: String,
    pub prev_receipt: String,
    /// Sealed first grant (the delivery response) and the request digest that took it.
    pub initial_grant: String,
    pub delivery_req: String,
    pub claim_op: String,
    pub saved_op: String,
    pub saved_reply: String,
    pub next_id: Id,
    /// Keyed digests of every token sealed for this session.
    pub digests: Vec<String>,
}

impl Control {
    pub fn closed_marker() -> Control {
        let mut c = Control {
            grant_id: String::new(),
            capability: String::new(),
            enc_pub: String::new(),
            sig_pub: String::new(),
            ctl: Ctl::new(0, 1),
            del: Del::new(),
            td: Td::new(),
            commit: String::new(),
            prev_commit: String::new(),
            receipt: String::new(),
            prev_receipt: String::new(),
            initial_grant: String::new(),
            delivery_req: String::new(),
            claim_op: String::new(),
            saved_op: String::new(),
            saved_reply: String::new(),
            next_id: 1,
            digests: vec![],
        };
        c.close();
        c
    }

    /// Closure: block delivery, renewal admission and completion; drop bindings,
    /// commitments and saved ciphertext; keep only the marker.
    pub fn close(&mut self) {
        if let Ok((n, _)) = renewal::step(&self.ctl, renewal::Ev::Close) {
            self.ctl = n;
        }
        if let Ok((n, _)) = delivery::step(&self.del, delivery::Ev::Block) {
            self.del = n;
        }
        if let Ok((n, _)) = scout_core::teardown::step(&self.td, scout_core::teardown::Ev::Close) {
            self.td = n;
        }
        for s in [
            &mut self.commit,
            &mut self.prev_commit,
            &mut self.receipt,
            &mut self.prev_receipt,
            &mut self.initial_grant,
            &mut self.claim_op,
            &mut self.saved_op,
            &mut self.saved_reply,
        ] {
            s.clear();
        }
        self.digests.clear();
    }
}

pub fn parse<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Option<T> {
    serde_json::from_slice(b).ok()
}

pub fn to_bytes<T: Serialize>(t: &T) -> Vec<u8> {
    serde_json::to_vec(t).unwrap_or_default()
}
