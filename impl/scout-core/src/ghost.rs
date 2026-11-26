// SPDX-License-Identifier: CC-BY-4.0

//! Specification-only wrappers: ghost history, invariants and safety predicates.
//! Compiled for Kani and for tests, never into production.
use crate::delivery::{self, Del, Phase as DPhase};
use crate::renewal::{self, Ctl, Phase};
use crate::session::{self, Sess, St};
use crate::teardown::{self, Td};
use crate::{Id, Reject};

// ---- session (F1-F4) ----

pub fn f1(s: &Sess) -> bool {
    !s.minted || s.key != 0
}
pub fn f2(s: &Sess) -> bool {
    !s.minted || (s.sealed_to == s.key && s.key != 0)
}
pub fn f3(a: &Sess, b: &Sess) -> bool {
    a.principal == 0 || b.principal == a.principal
}
pub fn f4(a: &Sess, r: &Result<Sess, Reject>) -> bool {
    !a.state.terminal() || r.is_err()
}

pub fn sess_inv(s: &Sess) -> bool {
    let live_minted = matches!(s.state, St::Authorized | St::Active);
    f1(s)
        && f2(s)
        && (!live_minted || (s.minted && s.principal != 0))
        && (s.state != St::Pending || (s.key == 0 && s.principal == 0 && !s.minted))
        && (s.state != St::Bound || (s.key != 0 && !s.minted))
        && (s.state != St::Denied || !s.minted)
        && (s.key != 0 || (s.principal == 0 && !s.minted))
        && (!s.minted || s.principal != 0)
}

/// Core step plus the F3/F4 step properties.
pub fn sess_apply(s: &Sess, e: session::Ev) -> Result<Sess, Reject> {
    let r = session::step(s, e);
    assert!(f4(s, &r));
    if let Ok(n) = &r {
        assert!(f3(s, n));
    }
    r
}

// ---- delivery (D1, D2) ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct GDel {
    pub d: Del,
    /// Ghost: the first response ever committed (0 = none).
    pub first: Id,
    /// Ghost: delivery has been revoked or closed.
    pub revoked: bool,
}

impl GDel {
    pub fn new() -> GDel {
        GDel { d: Del::new(), first: 0, revoked: false }
    }
    pub fn inv(&self) -> bool {
        let blocked = self.d.phase == DPhase::Blocked;
        self.revoked == blocked
            && match self.d.phase {
                DPhase::Fresh => self.first == 0 && self.d.resp == 0,
                DPhase::Committed => self.first != 0 && self.d.resp == self.first,
                DPhase::Blocked => self.d.resp == 0,
            }
    }
    /// D1: any released response is the first one.
    pub fn d1(&self, released: Id) -> bool {
        released != 0 && released == self.first
    }
    pub fn apply(&self, e: delivery::Ev) -> Result<(GDel, delivery::Out), Reject> {
        let r = delivery::step(&self.d, e);
        // D2: nothing is released once revoked.
        if self.revoked {
            assert!(!matches!(r, Ok((_, delivery::Out::Release(_)))));
        }
        let (d, out) = r?;
        let mut g = GDel { d, first: self.first, revoked: self.revoked || d.phase == DPhase::Blocked };
        if self.d.phase == DPhase::Fresh && d.phase == DPhase::Committed {
            g.first = d.resp;
        }
        if let delivery::Out::Release(x) = out {
            assert!(g.d1(x));
        }
        Ok((g, out))
    }
}

impl Default for GDel {
    fn default() -> Self {
        GDel::new()
    }
}

// ---- renewal (S1-S5, T3, T5) ----

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct GRen {
    pub c: Ctl,
    /// The symbolic generation the per-generation properties are stated for.
    pub g0: u32,
    pub admits: u8,
    pub exchanges: u8,
    /// The current reservation was admitted on a matching commitment.
    pub claim_cur: bool,
    /// Reply and operation of the commit g0 -> g0+1.
    pub committed: Id,
    pub committer: Id,
}

impl GRen {
    pub fn new(g0: u32, deadline: u64, commit: Id) -> GRen {
        GRen { c: Ctl::new(deadline, commit), g0, admits: 0, exchanges: 0, claim_cur: false, committed: 0, committer: 0 }
    }

    /// S1: at most one admission and one provider exchange per generation.
    pub fn s1(&self) -> bool {
        self.admits <= 1 && self.exchanges <= self.admits
    }
    /// S2: the client authentication is used only after admission on the current token.
    pub fn s2(&self) -> bool {
        !self.c.vol.exchanged || self.claim_cur
    }
    /// S3: a saved reply for generation g0+1 is the committed one, held for the committing operation.
    pub fn s3(&self) -> bool {
        self.c.gen != self.g0.wrapping_add(1)
            || self.g0 == u32::MAX
            || self.c.saved.reply == 0
            || (self.c.saved.reply == self.committed && self.c.saved.op == self.committer)
    }
    /// S4: closure leaves no reservation, commitment or saved reply.
    pub fn s4(&self) -> bool {
        self.c.phase != Phase::Closed
            || (self.c.claim_op == 0 && self.c.commit == 0 && self.c.saved == Default::default() && self.c.vol == Default::default())
    }
    /// S5 (state part): a READY record holds its saved reply.
    pub fn s5(&self) -> bool {
        (self.c.phase == Phase::Ready) == (self.c.saved.reply != 0 && self.c.saved.op != 0)
            && (self.c.saved.reply != 0) == (self.c.phase == Phase::Ready)
    }

    pub fn inv(&self) -> bool {
        let c = &self.c;
        let structural = ((c.phase == Phase::Refreshing || c.phase == Phase::Recovery) == (c.claim_op != 0))
            && (c.phase == Phase::Closed || c.commit != 0)
            && (!c.vol.exchanged || c.vol.inflight)
            && (!c.vol.inflight || (c.phase == Phase::Refreshing && self.claim_cur));
        let per_gen = if c.gen < self.g0 {
            self.admits == 0 && self.exchanges == 0 && self.committed == 0 && self.committer == 0
        } else if c.gen == self.g0 {
            let claimed = c.phase == Phase::Refreshing || c.phase == Phase::Recovery;
            self.committed == 0
                && self.committer == 0
                && (!matches!(c.phase, Phase::Active | Phase::Ready) || (self.admits == 0 && self.exchanges == 0))
                && (!claimed || (self.admits == 1 && self.claim_cur))
                && (!c.vol.exchanged || self.exchanges == 1)
                && (!(c.vol.inflight && self.exchanges == 1) || c.vol.exchanged)
        } else if self.g0.checked_add(1) == Some(c.gen) {
            self.admits == 1 && self.exchanges == 1 && self.committed != 0 && self.committer != 0
        } else {
            true
        };
        structural && per_gen && self.s1() && self.s2() && self.s3() && self.s4() && self.s5()
    }

    /// Core step plus ghost bookkeeping and the step-wise properties.
    pub fn apply(&self, e: renewal::Ev) -> Result<(GRen, renewal::Out), Reject> {
        let c = &self.c;
        let r = renewal::step(c, e);
        let closed = c.phase == Phase::Closed;
        // S4: nothing admitted, completed, replayed or retired after closure.
        if closed && !matches!(e, renewal::Ev::Crash | renewal::Ev::Close) {
            assert!(r.is_err());
        }
        // S5: a committed reply stays retrievable by its operation until retired.
        if let renewal::Ev::Begin { op, gen, now, prev_ok, .. } = e {
            if c.phase == Phase::Ready
                && c.saved.reply != 0
                && c.saved.op == op
                && gen.checked_add(1) == Some(c.gen)
                && prev_ok
                && now <= c.saved.until
            {
                assert!(matches!(r, Ok((_, renewal::Out::Replay(x))) if x == c.saved.reply));
            }
        }
        let (n, out) = r?;
        let mut g = *self;
        g.c = n;
        match (e, out) {
            (renewal::Ev::Begin { cur_ok, .. }, renewal::Out::Reserved) => {
                assert!(cur_ok); // S2
                if c.gen == self.g0 {
                    g.admits = g.admits.saturating_add(1);
                }
                g.claim_cur = cur_ok;
            }
            (renewal::Ev::Begin { op, gen, .. }, renewal::Out::Replay(x)) => {
                if gen == self.g0 {
                    assert!(x == self.committed && op == self.committer); // S3
                }
            }
            (renewal::Ev::Exchange, renewal::Out::Exchange) => {
                assert!(self.claim_cur); // S2
                if c.gen == self.g0 {
                    g.exchanges = g.exchanges.saturating_add(1);
                }
            }
            (renewal::Ev::Commit { op, reply, .. }, renewal::Out::Committed) => {
                if c.gen == self.g0 {
                    g.committed = reply;
                    g.committer = op;
                }
                g.claim_cur = false;
            }
            _ => {}
        }
        // S5: a saved reply disappears only by admission, closure or lapse.
        if c.saved.reply != 0 && n.saved.reply == 0 {
            assert!(match e {
                renewal::Ev::Begin { .. } => out == renewal::Out::Reserved,
                renewal::Ev::Close => true,
                renewal::Ev::Retire { now } => now > c.saved.until,
                _ => false,
            });
        }
        Ok((g, out))
    }
}

// ---- teardown (T1, T2, T4, T6) ----

pub fn td_inv(t: &Td) -> bool {
    (!t.deleted || (t.closed && !t.key)) && (t.key || t.deleted)
}

pub fn td_apply(t: &Td, e: teardown::Ev) -> Result<(Td, teardown::Out), Reject> {
    let r = teardown::step(t, e);
    if let (teardown::Ev::Gate { delivered }, Ok((_, teardown::Out::Attempt))) = (e, &r) {
        assert!(delivered); // T1
        assert!(t.key); // T6
    }
    if let (teardown::Ev::Delete, Ok(_)) = (e, &r) {
        assert!(t.closed); // T4
    }
    r
}

/// T2: reported revoked only on provider acknowledgement.
pub fn t2(o: teardown::Outcome) -> bool {
    (teardown::classify(o) == teardown::Reported::Revoked) == (o == teardown::Outcome::Ack)
}
