// SPDX-License-Identifier: Apache-2.0

//! Renewal control record (S1-S5, T3, T5):
//! ACTIVE(g) -> REFRESHING(g) -> READY(g+1) -> ACTIVE(g+1), plus RECOVERY and CLOSED.
use crate::{Id, Reject, RECOVERY_WINDOW};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Phase {
    Active,
    Refreshing,
    Ready,
    Recovery,
    Closed,
}

/// The reply committed by the last renewal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Saved {
    pub op: Id,
    pub reply: Id,
    pub until: u64,
}

/// Broker memory that a crash loses; the durable part never depends on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Vol {
    pub inflight: bool,
    pub exchanged: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Ctl {
    pub phase: Phase,
    pub gen: u32,
    pub deadline: u64,
    /// Commitment to the current refresh token (0 after closure).
    pub commit: Id,
    /// Operation holding the reservation (0 = none).
    pub claim_op: Id,
    pub saved: Saved,
    pub vol: Vol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Ev {
    /// `cur_ok`: presented token matches the committed commitment.
    /// `prev_ok`: it matches the commitment the saved reply was computed from.
    Begin {
        op: Id,
        gen: u32,
        now: u64,
        cur_ok: bool,
        prev_ok: bool,
    },
    /// About to call the provider with the client authentication.
    Exchange,
    /// The single conditional write: sealed reply, next commitment, next generation.
    Commit {
        op: Id,
        reply: Id,
        next_commit: Id,
        now: u64,
    },
    Crash,
    Close,
    Retire {
        now: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    None,
    Reserved,
    /// Return the saved reply to the committing operation.
    Replay(Id),
    /// Same operation, reservation without result: recovery now required.
    Ambiguous,
    Exchange,
    Committed,
}

impl Ctl {
    pub fn new(deadline: u64, commit: Id) -> Ctl {
        Ctl { phase: Phase::Active, gen: 0, deadline, commit, claim_op: 0, saved: Saved::default(), vol: Vol::default() }
    }
}

pub fn step(c: &Ctl, e: Ev) -> Result<(Ctl, Out), Reject> {
    let mut n = *c;
    match e {
        Ev::Crash => {
            n.vol = Vol::default();
            Ok((n, Out::None))
        }
        Ev::Close => {
            n.phase = Phase::Closed;
            n.commit = 0;
            n.claim_op = 0;
            n.saved = Saved::default();
            n.vol = Vol::default();
            Ok((n, Out::None))
        }
        _ if c.phase == Phase::Closed => Err(Reject::Closed),
        Ev::Retire { now } => {
            if c.saved.reply != 0 && now > c.saved.until {
                n.saved = Saved::default();
                if n.phase == Phase::Ready {
                    n.phase = Phase::Active;
                }
            }
            Ok((n, Out::None))
        }
        Ev::Exchange => {
            if c.phase != Phase::Refreshing || !c.vol.inflight || c.vol.exchanged {
                return Err(Reject::NoClaim);
            }
            n.vol.exchanged = true;
            Ok((n, Out::Exchange))
        }
        Ev::Commit { op, reply, next_commit, now } => {
            if c.phase != Phase::Refreshing || c.claim_op != op || !c.vol.inflight || !c.vol.exchanged {
                return Err(Reject::NoClaim);
            }
            if reply == 0 || next_commit == 0 {
                return Err(Reject::State);
            }
            n.gen = c.gen.checked_add(1).ok_or(Reject::State)?;
            n.commit = next_commit;
            n.phase = Phase::Ready;
            n.claim_op = 0;
            n.saved = Saved { op, reply, until: now.saturating_add(RECOVERY_WINDOW).min(c.deadline) };
            n.vol = Vol::default();
            Ok((n, Out::Committed))
        }
        Ev::Begin { op, gen, now, cur_ok, prev_ok } => {
            if c.phase == Phase::Ready && c.saved.reply != 0 && c.saved.op == op && gen.checked_add(1) == Some(c.gen) {
                if !prev_ok {
                    return Err(Reject::Commitment);
                }
                if now > c.saved.until {
                    return Err(Reject::Lapsed);
                }
                return Ok((n, Out::Replay(c.saved.reply)));
            }
            if now >= c.deadline {
                return Err(Reject::Expired);
            }
            if c.phase == Phase::Recovery {
                return Err(Reject::Recovery);
            }
            if gen != c.gen {
                return Err(Reject::Stale);
            }
            #[cfg(not(feature = "broken-variants"))]
            if !cur_ok {
                return Err(Reject::Commitment);
            }
            #[cfg(feature = "broken-variants")]
            let _ = cur_ok; // broken S2: no commitment check
            if c.phase == Phase::Refreshing {
                if c.claim_op != op {
                    return Err(Reject::Competing);
                }
                if c.vol.inflight {
                    return Err(Reject::InProgress);
                }
                n.phase = Phase::Recovery;
                return Ok((n, Out::Ambiguous));
            }
            if op == 0 {
                return Err(Reject::State);
            }
            n.phase = Phase::Refreshing;
            n.claim_op = op;
            n.saved = Saved::default();
            n.vol = Vol { inflight: true, exchanged: false };
            Ok((n, Out::Reserved))
        }
    }
}
