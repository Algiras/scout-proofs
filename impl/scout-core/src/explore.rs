// SPDX-License-Identifier: Apache-2.0

//! Ordinary-test counterparts of the Kani harnesses: breadth-first exploration
//! of reachable states, and the inductive step checked over every state of a
//! small universe that satisfies the invariant.
use crate::delivery::{self, Del, Phase as DPhase};
use crate::ghost::*;
use crate::renewal::{self, Ctl, Phase, Saved, Vol};
use crate::session::{self, Sess, St};
use crate::teardown::{self, Outcome, Td};
use std::collections::{HashSet, VecDeque};
use std::fmt::Debug;

fn bfs<S: Copy + Debug>(init: S, events: &[S], next: impl Fn(&S, usize) -> Option<S>, inv: impl Fn(&S) -> bool) -> (usize, usize) {
    let _ = events;
    let mut seen = HashSet::new();
    let mut q = VecDeque::new();
    seen.insert(format!("{init:?}"));
    q.push_back(init);
    let mut transitions = 0;
    while let Some(s) = q.pop_front() {
        assert!(inv(&s), "invariant violated in {s:?}");
        for i in 0.. {
            let Some(n) = next(&s, i) else { break };
            transitions += 1;
            if seen.insert(format!("{n:?}")) {
                q.push_back(n);
            }
        }
    }
    (seen.len(), transitions)
}

fn ren_events() -> Vec<renewal::Ev> {
    use renewal::Ev::*;
    let mut v = vec![Exchange, Crash, Close];
    for now in [0, 700, 2000] {
        v.push(Retire { now });
        for op in 1..=2 {
            for gen in 0..=3 {
                for cur_ok in [false, true] {
                    for prev_ok in [false, true] {
                        v.push(Begin { op, gen, now, cur_ok, prev_ok });
                    }
                }
            }
            for reply in 1..=2 {
                v.push(Commit { op, reply, next_commit: 1 + (op + reply) % 2, now });
            }
        }
    }
    v
}

#[test]
fn renewal_reachable_states_satisfy_inv() {
    let evs = ren_events();
    let (mut states, mut trans) = (0, 0);
    for g0 in 0..=2 {
        // Events that would exceed generation 3 are skipped to keep the space finite.
        let next = |g: &GRen, i: usize| -> Option<GRen> {
            let e = evs.get(i)?;
            Some(match g.apply(*e) {
                Ok((n, _)) if n.c.gen <= 3 => n,
                _ => *g,
            })
        };
        let (s, t) = bfs(GRen::new(g0, 1000, 1), &[], next, |g| g.inv());
        states += s;
        trans += t;
    }
    println!("renewal S1-S5 reachable: states={states} transitions={trans}");
    assert!(states > 100);
}

#[test]
fn renewal_inductive_step_over_small_universe() {
    let evs = ren_events();
    let (mut checked, mut steps) = (0u64, 0u64);
    for g0 in 0..=1u32 {
        for gen in 0..=2u32 {
            for phase in [Phase::Active, Phase::Refreshing, Phase::Ready, Phase::Recovery, Phase::Closed] {
                for commit in 0..=1 {
                    for claim_op in 0..=2 {
                        for (sop, srep, until) in iproduct3() {
                            for (inflight, exchanged) in [(false, false), (true, false), (true, true), (false, true)] {
                                for (admits, exchanges, committed, committer) in quad() {
                                    for claim_cur in [false, true] {
                                        let g = GRen {
                                            c: Ctl {
                                                phase,
                                                gen,
                                                deadline: 1000,
                                                commit,
                                                claim_op,
                                                saved: Saved { op: sop, reply: srep, until },
                                                vol: Vol { inflight, exchanged },
                                            },
                                            g0,
                                            admits,
                                            exchanges,
                                            claim_cur,
                                            committed,
                                            committer,
                                        };
                                        if !g.inv() {
                                            continue;
                                        }
                                        checked += 1;
                                        for e in &evs {
                                            if let Ok((n, _)) = g.apply(*e) {
                                                steps += 1;
                                                assert!(n.inv(), "not inductive: {g:?} --{e:?}--> {n:?}");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("renewal inductive: invariant states={checked} successful steps checked={steps}");
    assert!(checked > 100);
}

fn iproduct3() -> Vec<(u32, u32, u64)> {
    let mut v = vec![];
    for a in 0..=2 {
        for b in 0..=2 {
            for u in [0, 600] {
                v.push((a, b, u));
            }
        }
    }
    v
}

fn quad() -> Vec<(u8, u8, u32, u32)> {
    let mut v = vec![];
    for a in 0..=2 {
        for e in 0..=2 {
            for c in 0..=2 {
                for d in 0..=2 {
                    v.push((a, e, c, d));
                }
            }
        }
    }
    v
}

fn sess_events() -> Vec<session::Ev> {
    use session::Ev::*;
    let mut v = vec![Deliver, Deny, Revoke, Tick { now: 0 }, Tick { now: 10 }];
    for k in 0..=2 {
        v.push(Bind { key: k });
        v.push(Consent { principal: k });
        v.push(Authorize { seal_key: k });
    }
    v
}

#[test]
fn session_reachable_and_inductive() {
    let evs = sess_events();
    let next = |s: &Sess, i: usize| -> Option<Sess> {
        let e = evs.get(i)?;
        Some(sess_apply(s, *e).unwrap_or(*s))
    };
    let (states, trans) = bfs(Sess::new(10), &[], next, sess_inv);
    println!("session F1-F4 reachable: states={states} transitions={trans}");
    let mut checked = 0;
    for state in [St::Pending, St::Bound, St::Authorized, St::Active, St::Denied, St::Revoked, St::Expired] {
        for key in 0..=2 {
            for principal in 0..=2 {
                for minted in [false, true] {
                    for sealed_to in 0..=2 {
                        let s = Sess { state, deadline: 10, key, principal, minted, sealed_to };
                        if !sess_inv(&s) {
                            continue;
                        }
                        checked += 1;
                        for e in &evs {
                            if let Ok(n) = sess_apply(&s, *e) {
                                assert!(sess_inv(&n), "not inductive: {s:?} --{e:?}--> {n:?}");
                            }
                        }
                    }
                }
            }
        }
    }
    println!("session inductive: invariant states={checked}");
}

#[test]
fn delivery_reachable_and_inductive() {
    let evs: Vec<delivery::Ev> = vec![
        delivery::Ev::Block,
        delivery::Ev::Fetch { same: true, resp: 1 },
        delivery::Ev::Fetch { same: false, resp: 1 },
        delivery::Ev::Fetch { same: true, resp: 2 },
        delivery::Ev::Fetch { same: false, resp: 2 },
        delivery::Ev::Fetch { same: true, resp: 0 },
    ];
    let next = |g: &GDel, i: usize| -> Option<GDel> {
        let e = evs.get(i)?;
        Some(g.apply(*e).map(|x| x.0).unwrap_or(*g))
    };
    let (states, trans) = bfs(GDel::new(), &[], next, |g| g.inv());
    println!("delivery D1-D2 reachable: states={states} transitions={trans}");
    for phase in [DPhase::Fresh, DPhase::Committed, DPhase::Blocked] {
        for resp in 0..=2 {
            for first in 0..=2 {
                for revoked in [false, true] {
                    let g = GDel { d: Del { phase, resp }, first, revoked };
                    if g.inv() {
                        for e in &evs {
                            if let Ok((n, _)) = g.apply(*e) {
                                assert!(n.inv(), "not inductive: {g:?} --{e:?}--> {n:?}");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn teardown_reachable_and_inductive() {
    let evs = [teardown::Ev::Gate { delivered: true }, teardown::Ev::Gate { delivered: false }, teardown::Ev::Close, teardown::Ev::Delete];
    let next = |t: &Td, i: usize| -> Option<Td> {
        let e = evs.get(i)?;
        Some(td_apply(t, *e).map(|x| x.0).unwrap_or(*t))
    };
    let (states, trans) = bfs(Td::new(), &[], next, td_inv);
    println!("teardown T1,T4,T6 reachable: states={states} transitions={trans}");
    for (key, closed, deleted) in [
        (false, false, false),
        (false, false, true),
        (false, true, false),
        (false, true, true),
        (true, false, false),
        (true, false, true),
        (true, true, false),
        (true, true, true),
    ] {
        let t = Td { key, closed, deleted };
        if td_inv(&t) {
            for e in evs {
                if let Ok((n, _)) = td_apply(&t, e) {
                    assert!(td_inv(&n));
                }
            }
        }
    }
    for o in [Outcome::Ack, Outcome::Unsupported, Outcome::Failed, Outcome::Unknown] {
        assert!(t2(o));
    }
}

#[test]
fn closure_blocks_everything() {
    let g = GRen::new(0, 1000, 1);
    let (g, _) = g.apply(renewal::Ev::Close).unwrap();
    assert!(g.s4());
    for e in ren_events() {
        if !matches!(e, renewal::Ev::Crash | renewal::Ev::Close) {
            assert!(g.apply(e).is_err());
        }
    }
    let (d, _) = GDel::new().apply(delivery::Ev::Block).unwrap();
    assert!(d.apply(delivery::Ev::Fetch { same: true, resp: 1 }).is_err());
}
