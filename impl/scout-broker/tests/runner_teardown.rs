// SPDX-License-Identifier: Apache-2.0

//! Runner guarantees: teardown on signals and panics, process-group cleanup, bound replies, recoverable renewal.
mod support;

use scout_broker::store::Store;
use scout_runner::{CallErr, Client, Options};
use scout_wire::http::{Transport, Ureq};
use scout_wire::{b64, seal, Error};
use serde_json::json;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::*;

#[test]
fn real_runner_revokes_and_finalizes_on_sigterm_sigint_and_sighup() {
    let live = Live::start(8);
    for (idx, (sig, code)) in [("TERM", 143), ("INT", 130), ("HUP", 129)].into_iter().enumerate() {
        let pidfile = live.dir.join(format!("pid-{sig}"));
        let script = format!("echo $$ > {}; exec sleep 300", pidfile.display());
        let mut run = Proc::spawn(
            &live.dir,
            &format!("run-{sig}"),
            "scout-run",
            &[
                "--broker",
                &live.broker,
                "--auto-consent",
                "true",
                "--poll-every",
                "1",
                "--renew-margin",
                "5",
                "--",
                "/bin/sh",
                "-c",
                &script,
            ],
            &[],
        );
        let pid = wait_file(&pidfile, 20);
        assert!(alive(&pid));
        let sent = Command::new("kill").args([format!("-{sig}"), run.child.id().to_string()]).status().unwrap();
        assert!(sent.success());
        assert_eq!(run.wait(Duration::from_secs(15)), Some(code), "SIG{sig}: runner output {}", run.text());
        assert!(gone_within(&pid, 3), "SIG{sig}: the workload survived the runner");
        assert_eq!(live.stats()["families"][idx]["revoked"], true, "SIG{sig}: the token family was not revoked");
        let finalized = live.procs[1].text().lines().filter(|l| l.contains("/finalize 200")).count();
        assert_eq!(finalized, idx + 1, "SIG{sig}: broker saw {finalized} finalizations");
        assert!(run.text().contains("session finalized"), "{}", run.text());
    }
}

fn group_survivor_test(trap: bool) {
    let st = Stack::new();
    let dir = temp_dir("group");
    let pidfile = dir.join("bg.pid");
    let script = format!("{}sleep 300 & echo $! > {}; exit 0", if trap { "trap '' TERM; " } else { "" }, pidfile.display());
    let mut c = Client::with_ureq(&st.url());
    let o = Options {
        auto_consent: true,
        command: vec!["/bin/sh".into(), "-c".into(), script],
        poll_every: Duration::from_millis(200),
        kill_grace: Duration::from_secs(1),
        ..Default::default()
    };
    let start = Instant::now();
    assert_eq!(scout_runner::run(&mut c, &o), 0);
    let pid = wait_file(&pidfile, 5);
    assert!(gone_within(&pid, 3), "a background member of the process group survived (trap {trap})");
    assert!(start.elapsed() < Duration::from_secs(15));
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn background_group_members_are_stopped_when_the_leader_exits() {
    group_survivor_test(false);
}

#[test]
fn group_members_that_ignore_sigterm_are_killed_after_the_grace_period() {
    group_survivor_test(true);
}

struct PanicWhenStarted {
    pidfile: std::path::PathBuf,
    fired: AtomicUsize,
}

impl Transport for PanicWhenStarted {
    fn call(&self, m: &str, u: &str, h: &[(&str, &str)], b: &[u8]) -> Result<(u16, Vec<u8>), Error> {
        if u.ends_with("/status") && self.pidfile.exists() && self.fired.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("injected failure in the supervision loop");
        }
        (Ureq { redirects: 0 }).call(m, u, h, b)
    }
}

#[test]
fn a_panic_in_the_runner_still_stops_the_workload_revokes_and_finalizes() {
    let st = Stack::new();
    let dir = temp_dir("panic");
    let pidfile = dir.join("w.pid");
    let tr = Arc::new(PanicWhenStarted { pidfile: pidfile.clone(), fired: AtomicUsize::new(0) });
    let mut c = Client::new(&st.url(), tr);
    let o = Options {
        auto_consent: true,
        command: vec!["/bin/sh".into(), "-c".into(), format!("echo $$ > {}; exec sleep 300", pidfile.display())],
        poll_every: Duration::from_millis(200),
        kill_grace: Duration::from_secs(1),
        ..Default::default()
    };
    assert_eq!(scout_runner::run(&mut c, &o), 70);
    let pid = wait_file(&pidfile, 5);
    assert!(gone_within(&pid, 3), "the workload survived the panic");
    assert_eq!(st.stats()["families"][0]["revoked"], true);
    assert!(!st.store().dump().contains_key(&format!("sess/{}", c.session)), "session not finalized");
    std::fs::remove_dir_all(dir).ok();
}

/// Forwards to the broker, except that a /renew reply can be replaced.
#[derive(Default)]
struct Swap {
    replace: Mutex<Option<Vec<u8>>>,
    replies: Mutex<Vec<Vec<u8>>>,
}

impl Transport for Swap {
    fn call(&self, m: &str, u: &str, h: &[(&str, &str)], b: &[u8]) -> Result<(u16, Vec<u8>), Error> {
        if u.ends_with("/renew") {
            if let Some(r) = self.replace.lock().unwrap().clone() {
                return Ok((200, r));
            }
        }
        let r = (Ureq { redirects: 0 }).call(m, u, h, b)?;
        if u.ends_with("/renew") && r.0 == 200 {
            self.replies.lock().unwrap().push(r.1.clone());
        }
        Ok(r)
    }
}

fn crafted(c: &Client, grant: &str, generation: u32, expires_in: u64) -> Vec<u8> {
    let seal_to =
        |t: &str, kind: &str| b64(&seal::seal(t.as_bytes(), &c.enc_pub, &seal::aad(&c.session, grant, kind, generation)).unwrap());
    serde_json::to_vec(&json!({
        "session": c.session, "grant": grant, "capability": "default", "generation": generation, "receipt": "r",
        "access": { "sealed": seal_to("at_crafted", "access"), "expiresIn": expires_in },
        "refresh": { "sealed": seal_to("rt_crafted", "refresh") },
    }))
    .unwrap()
}

#[test]
fn a_replayed_older_reply_is_not_accepted_as_the_next_generation() {
    let st = Stack::new();
    let sw = Arc::new(Swap::default());
    let (c, g0) = st.onboard_with(sw.clone());
    let g1 = c.renew(&g0, "op-1").unwrap();
    let g2 = c.renew(&g1, "op-2").unwrap();
    assert_eq!(g2.generation, 2);
    *sw.replace.lock().unwrap() = Some(sw.replies.lock().unwrap()[0].clone());
    let err = c.renew(&g2, "op-3").unwrap_err();
    assert!(err.to_string().contains("unexpected generation"), "{err}");
}

#[test]
fn replies_for_another_grant_or_generation_and_huge_lifetimes_are_handled() {
    let st = Stack::new();
    let sw = Arc::new(Swap::default());
    let (c, g0) = st.onboard_with(sw.clone());
    let set = |b: Vec<u8>| *sw.replace.lock().unwrap() = Some(b);
    set(crafted(&c, "some-other-grant", 1, 60));
    let err = c.renew(&g0, "op-1").unwrap_err();
    assert!(err.to_string().contains("wrong grant"), "{err}");
    set(crafted(&c, &c.grant_id, 5, 60));
    assert!(c.renew(&g0, "op-2").unwrap_err().to_string().contains("unexpected generation"));
    set(crafted(&c, &c.grant_id, 0, 60));
    assert!(c.renew(&g0, "op-3").is_err(), "the same generation again is not a renewal");
    let now = (c.clock)();
    for ttl in [u64::MAX, u64::MAX - now + 5, 10 * 24 * 3600] {
        set(crafted(&c, &c.grant_id, 1, ttl));
        let g = c.renew(&g0, "op-4").unwrap();
        assert_eq!(g.generation, 1);
        assert!(g.access_expires <= (c.clock)() + 24 * 3600, "expiresIn {ttl} was not clamped: {}", g.access_expires);
        assert!(g.access_expires >= now, "expiry wrapped around");
    }
}

/// Reaches the broker for the first /renew and drops its reply, then is unreachable for `down` calls.
struct Flaky {
    calls: AtomicUsize,
    down: usize,
}

impl Transport for Flaky {
    fn call(&self, m: &str, u: &str, h: &[(&str, &str)], b: &[u8]) -> Result<(u16, Vec<u8>), Error> {
        if !u.ends_with("/renew") {
            return (Ureq { redirects: 0 }).call(m, u, h, b);
        }
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            let _ = (Ureq { redirects: 0 }).call(m, u, h, b)?;
            return Err(Error("reply dropped".into()));
        }
        if n <= self.down {
            return Err(Error("broker unreachable".into()));
        }
        (Ureq { redirects: 0 }).call(m, u, h, b)
    }
}

#[test]
fn a_pending_operation_survives_a_long_outage_and_is_recovered_with_one_refresh() {
    let st = Stack::new();
    let fl = Arc::new(Flaky { calls: AtomicUsize::new(0), down: 6 });
    let (c, g0) = st.onboard_with(fl);
    let first = c.renew_recoverable(&g0, 5, Duration::from_millis(1));
    assert!(matches!(first, Err(CallErr::Transport(_))), "{first:?}");
    assert_eq!(st.family_calls(), vec![1]);
    let g1 = c.renew_recoverable(&g0, 5, Duration::from_millis(1)).expect("the saved reply must still be replayable");
    assert_eq!(g1.generation, 1);
    assert_eq!(st.family_calls(), vec![1], "one provider refresh for the generation");
    assert_eq!(st.whoami(&g1.access), 200);
}

#[test]
fn the_supervisor_keeps_retrying_a_transient_renewal_failure() {
    let st = Stack::with_access_ttl(4);
    let fl = Arc::new(Flaky { calls: AtomicUsize::new(0), down: 6 });
    let mut c = Client::new(&st.url(), fl);
    let o = Options {
        auto_consent: true,
        command: vec!["/bin/sh".into(), "-c".into(), "sleep 11".into()],
        renew_margin: 3,
        poll_every: Duration::from_millis(300),
        ..Default::default()
    };
    assert_eq!(scout_runner::run(&mut c, &o), 0, "the workload must not be stopped for a recoverable outage");
    assert!(st.family_calls()[0] >= 1, "the renewal completed");
}
