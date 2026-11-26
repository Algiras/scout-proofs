// SPDX-License-Identifier: Apache-2.0

//! Delivery record (D1, D2): the first authorized fetch commits one response.
use crate::{Id, Reject};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Phase {
    Fresh,
    Committed,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Del {
    pub phase: Phase,
    /// Committed response (0 unless Committed).
    pub resp: Id,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Ev {
    /// `same`: the request is identical to the one that committed the response.
    Fetch { same: bool, resp: Id },
    /// Revocation or closure.
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    None,
    Release(Id),
    /// A different valid request arrived: release nothing and revoke the session.
    RevokeSession,
}

impl Del {
    pub fn new() -> Del {
        Del { phase: Phase::Fresh, resp: 0 }
    }
}

impl Default for Del {
    fn default() -> Self {
        Del::new()
    }
}

pub fn step(d: &Del, e: Ev) -> Result<(Del, Out), Reject> {
    match (d.phase, e) {
        (Phase::Blocked, Ev::Fetch { .. }) => Err(Reject::Blocked),
        (_, Ev::Block) => Ok((Del { phase: Phase::Blocked, resp: 0 }, Out::None)),
        (Phase::Fresh, Ev::Fetch { resp, .. }) if resp != 0 => Ok((Del { phase: Phase::Committed, resp }, Out::Release(resp))),
        (Phase::Fresh, Ev::Fetch { .. }) => Err(Reject::State),
        #[cfg(not(feature = "broken-variants"))]
        (Phase::Committed, Ev::Fetch { same: true, .. }) => Ok((*d, Out::Release(d.resp))),
        #[cfg(feature = "broken-variants")]
        (Phase::Committed, Ev::Fetch { same: true, resp }) => Ok((*d, Out::Release(resp))), // broken D1
        (Phase::Committed, Ev::Fetch { same: false, .. }) => Ok((Del { phase: Phase::Blocked, resp: 0 }, Out::RevokeSession)),
    }
}
