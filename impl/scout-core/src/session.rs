// SPDX-License-Identifier: Apache-2.0

//! Session lifecycle reducer (F1-F4).
use crate::{Id, Reject};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum St {
    Pending,
    Bound,
    Authorized,
    Active,
    Denied,
    Revoked,
    Expired,
}

impl St {
    pub fn terminal(self) -> bool {
        matches!(self, St::Denied | St::Revoked | St::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Sess {
    pub state: St,
    pub deadline: u64,
    /// Pinned runner key (0 = not pinned).
    pub key: Id,
    /// Locked principal (0 = none yet).
    pub principal: Id,
    /// Tokens exist for this session.
    pub minted: bool,
    /// Key the tokens were sealed to (0 = none).
    pub sealed_to: Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Ev {
    Bind { key: Id },
    Consent { principal: Id },
    Authorize { seal_key: Id },
    Deliver,
    Deny,
    Revoke,
    Tick { now: u64 },
}

impl Sess {
    pub fn new(deadline: u64) -> Sess {
        Sess { state: St::Pending, deadline, key: 0, principal: 0, minted: false, sealed_to: 0 }
    }
}

pub fn step(s: &Sess, e: Ev) -> Result<Sess, Reject> {
    if s.state.terminal() {
        return Err(Reject::State);
    }
    let mut n = *s;
    match (s.state, e) {
        (St::Pending, Ev::Bind { key }) if key != 0 => {
            n.key = key;
            n.state = St::Bound;
        }
        (St::Pending, Ev::Consent { .. }) => return Err(Reject::NotBound),
        #[cfg(not(feature = "broken-variants"))]
        (St::Bound, Ev::Consent { principal }) => {
            if principal == 0 || (s.principal != 0 && s.principal != principal) {
                return Err(Reject::Principal);
            }
            n.principal = principal;
        }
        #[cfg(feature = "broken-variants")]
        (St::Bound, Ev::Consent { principal }) => {
            n.principal = principal; // broken F3: no principal lock
        }
        (St::Bound, Ev::Authorize { seal_key }) => {
            if s.principal == 0 || seal_key != s.key {
                return Err(Reject::Key);
            }
            n.minted = true;
            n.sealed_to = seal_key;
            n.state = St::Authorized;
        }
        (St::Authorized, Ev::Deliver) => n.state = St::Active,
        (St::Pending | St::Bound, Ev::Deny) => n.state = St::Denied,
        (_, Ev::Revoke) => n.state = St::Revoked,
        (_, Ev::Tick { now }) if now >= s.deadline => n.state = St::Expired,
        (_, Ev::Tick { .. }) => {}
        _ => return Err(Reject::State),
    }
    Ok(n)
}

/// A grant may be fetched while the session is AUTHORIZED or ACTIVE.
pub fn deliverable(s: &Sess) -> bool {
    matches!(s.state, St::Authorized | St::Active)
}

/// Renewal is admitted only for an ACTIVE session.
pub fn renewable(s: &Sess) -> bool {
    s.state == St::Active
}
