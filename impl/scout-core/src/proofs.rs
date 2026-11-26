// SPDX-License-Identifier: Apache-2.0

//! Kani harnesses. Each `*_inductive` harness assumes an arbitrary state that
//! satisfies the invariant, applies one arbitrary event and asserts the invariant,
//! so the result holds for any number of steps. Run: see the README.
use crate::delivery;
use crate::ghost::*;
use crate::renewal;
use crate::session::{self, Sess};
use crate::teardown;

// ---- session F1-F4 ----

#[kani::proof]
fn session_init_satisfies_invariant() {
    let deadline: u64 = kani::any();
    assert!(sess_inv(&Sess::new(deadline)));
}

#[kani::proof]
fn session_inductive_f1_f2() {
    let s: Sess = kani::any();
    let e: session::Ev = kani::any();
    kani::assume(sess_inv(&s));
    if let Ok(n) = sess_apply(&s, e) {
        assert!(sess_inv(&n));
    }
}

#[kani::proof]
fn session_invariant_implies_f1_f2() {
    let s: Sess = kani::any();
    kani::assume(sess_inv(&s));
    assert!(f1(&s) && f2(&s));
}

#[kani::proof]
fn session_f3_one_principal() {
    let s: Sess = kani::any();
    let e: session::Ev = kani::any();
    if let Ok(n) = session::step(&s, e) {
        assert!(f3(&s, &n));
    }
}

#[kani::proof]
fn session_f4_terminal_absorbing() {
    let s: Sess = kani::any();
    let e: session::Ev = kani::any();
    kani::assume(s.state.terminal());
    assert!(session::step(&s, e).is_err());
}

// ---- delivery D1-D2 ----

#[kani::proof]
fn delivery_init_satisfies_invariant() {
    assert!(GDel::new().inv());
}

#[kani::proof]
fn delivery_inductive_d1_d2() {
    let g: GDel = kani::any();
    let e: delivery::Ev = kani::any();
    kani::assume(g.inv());
    if let Ok((n, _)) = g.apply(e) {
        assert!(n.inv());
    }
}

#[kani::proof]
fn delivery_d2_nothing_after_revocation() {
    let g: GDel = kani::any();
    let e: delivery::Ev = kani::any();
    kani::assume(g.inv() && g.revoked);
    assert!(g.apply(e).is_err() || matches!(e, delivery::Ev::Block));
}

// ---- renewal S1-S5 ----

#[kani::proof]
fn renewal_init_satisfies_invariant() {
    let (g0, deadline, commit): (u32, u64, u32) = (kani::any(), kani::any(), kani::any());
    kani::assume(commit != 0);
    assert!(GRen::new(g0, deadline, commit).inv());
}

#[kani::proof]
fn renewal_inductive_s1_to_s5() {
    let g: GRen = kani::any();
    let e: renewal::Ev = kani::any();
    kani::assume(g.inv());
    if let Ok((n, _)) = g.apply(e) {
        assert!(n.inv());
    }
}

#[kani::proof]
fn renewal_invariant_implies_s1_to_s5() {
    let g: GRen = kani::any();
    kani::assume(g.inv());
    assert!(g.s1() && g.s2() && g.s3() && g.s4() && g.s5());
}

// ---- teardown T1-T6 (T3 and T5 are the closed-record clauses of S4 and D2) ----

#[kani::proof]
fn teardown_inductive_t1_t4_t6() {
    let t: teardown::Td = kani::any();
    let e: teardown::Ev = kani::any();
    kani::assume(td_inv(&t));
    if let Ok((n, _)) = td_apply(&t, e) {
        assert!(td_inv(&n));
    }
}

#[kani::proof]
fn teardown_t2_revoked_only_on_ack() {
    let o: teardown::Outcome = kani::any();
    assert!(t2(o));
}

#[kani::proof]
fn closure_t3_t5_no_work_after_close() {
    let g: GRen = kani::any();
    let d: GDel = kani::any();
    let e: renewal::Ev = kani::any();
    let f: delivery::Ev = kani::any();
    kani::assume(g.inv() && d.inv());
    let (closed, _) = g.apply(renewal::Ev::Close).unwrap();
    let (blocked, _) = d.apply(delivery::Ev::Block).unwrap();
    assert!(closed.s4() && blocked.d.resp == 0);
    if !matches!(e, renewal::Ev::Crash | renewal::Ev::Close) {
        assert!(closed.apply(e).is_err());
    }
    if let delivery::Ev::Fetch { .. } = f {
        assert!(blocked.apply(f).is_err());
    }
}

// ---- deliberately broken variants: each must FAIL (build with --features broken-variants) ----

#[cfg(feature = "broken-variants")]
#[kani::proof]
#[kani::should_panic]
fn broken_f3_no_principal_lock() {
    let s: Sess = kani::any();
    let e: session::Ev = kani::any();
    if let Ok(n) = session::step(&s, e) {
        assert!(f3(&s, &n));
    }
}

#[cfg(feature = "broken-variants")]
#[kani::proof]
#[kani::should_panic]
fn broken_d1_new_request_gets_new_response() {
    let g: GDel = kani::any();
    let e: delivery::Ev = kani::any();
    kani::assume(g.inv());
    let _ = g.apply(e);
}

#[cfg(feature = "broken-variants")]
#[kani::proof]
#[kani::should_panic]
fn broken_s2_no_commitment_check() {
    let g: GRen = kani::any();
    let e: renewal::Ev = kani::any();
    kani::assume(g.inv());
    let _ = g.apply(e);
}

#[cfg(feature = "broken-variants")]
#[kani::proof]
#[kani::should_panic]
fn broken_t1_revoke_any_token() {
    let t: teardown::Td = kani::any();
    let e: teardown::Ev = kani::any();
    kani::assume(td_inv(&t));
    let _ = td_apply(&t, e);
}
