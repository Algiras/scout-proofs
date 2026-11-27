// SPDX-License-Identifier: Apache-2.0

use crate::{signals, CallErr, Client, Grant};
use nix::errno::Errno;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use scout_wire::http::{Transport, Ureq};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub struct Options {
    pub principal: String,
    pub ttl: u64,
    pub auto_consent: bool,
    /// Existing session to bind (split creation): (session id, secret).
    pub bind: Option<(String, String)>,
    pub command: Vec<String>,
    pub poll_every: Duration,
    pub renew_margin: u64,
    pub max_failed_polls: u32,
    pub kill_grace: Duration,
    pub consent_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            principal: "demo-user".into(),
            ttl: 3600,
            auto_consent: false,
            bind: None,
            command: vec![],
            poll_every: Duration::from_secs(2),
            renew_margin: 30,
            max_failed_polls: 6,
            kill_grace: Duration::from_secs(5),
            consent_timeout: Duration::from_secs(300),
        }
    }
}

fn log(m: &str) {
    eprintln!("scout-run: {m}");
}

const TERMINAL: [&str; 3] = ["DENIED", "REVOKED", "EXPIRED"];

/// Runs the whole flow and always attempts revocation and finalization once a session exists,
/// including after SIGTERM, SIGINT, SIGHUP or a panic. Returns the child's exit code, 128 plus the
/// signal number, or a nonzero failure code.
pub fn run(c: &mut Client, o: &Options) -> i32 {
    let mut held: Vec<(String, String)> = vec![];
    let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drive(c, o, &mut held))).unwrap_or_else(|_| {
        log("internal error; tearing down");
        70
    });
    if !c.session.is_empty() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| teardown(c, &held)));
    }
    code
}

fn interrupted() -> Option<i32> {
    signals::received().map(|s| {
        log(&format!("received signal {s}; stopping"));
        128 + s
    })
}

fn teardown(c: &Client, held: &[(String, String)]) {
    let toks: Vec<(&str, &str)> = held.iter().map(|(k, t)| (k.as_str(), t.as_str())).collect();
    if !toks.is_empty() {
        match c.revoke(&toks) {
            Ok(out) => log(&format!("revocation outcomes: {}", out.iter().map(|(k, o)| format!("{k}={o}")).collect::<Vec<_>>().join(" "))),
            Err(e) => log(&format!("revocation failed: {e}")),
        }
    }
    match c.finalize() {
        Ok(()) => log("session finalized"),
        Err(e) => log(&format!("finalize failed: {e}")),
    }
}

fn drive(c: &mut Client, o: &Options, held: &mut Vec<(String, String)>) -> i32 {
    // The broker may still be starting: retry transport failures for a while.
    let mut created = Err(CallErr::Transport("not attempted".into()));
    for _ in 0..30 {
        created = match &o.bind {
            Some((id, secret)) => c.bind(id, secret),
            None => c.create(o.ttl),
        };
        if !matches!(created, Err(CallErr::Transport(_))) {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
        if let Some(code) = interrupted() {
            return code;
        }
    }
    if let Err(e) = created {
        log(&format!("cannot start session: {e}"));
        return 70;
    }
    let url = c.consent_url(&o.principal);
    log(&format!("consent URL: {url}"));
    if o.auto_consent {
        let u = url.clone();
        std::thread::spawn(move || {
            if let Err(e) = (Ureq { redirects: 5 }).call("GET", &u, &[], &[]) {
                log(&format!("auto-consent failed: {e}"));
            }
        });
    }
    let start = Instant::now();
    loop {
        match c.status() {
            Ok(s) if s.state == "AUTHORIZED" || s.state == "ACTIVE" => {
                c.deadline = s.deadline;
                break;
            }
            Ok(s) if TERMINAL.contains(&s.state.as_str()) => {
                log(&format!("session {}", s.state));
                return 71;
            }
            _ => {}
        }
        if start.elapsed() > o.consent_timeout {
            log("consent timed out");
            return 72;
        }
        std::thread::sleep(Duration::from_millis(300));
        if let Some(code) = interrupted() {
            return code;
        }
    }
    let mut g = match c.fetch_grant() {
        Ok(g) => g,
        Err(e) => {
            log(&format!("grant delivery failed: {e}"));
            return 73;
        }
    };
    held.push(("access".into(), g.access.clone()));
    held.push(("refresh".into(), g.refresh.clone()));
    let Some((prog, args)) = o.command.split_first() else {
        log("no command given");
        return 64;
    };
    // Minimal environment: nothing inherited, only the access token.
    let child = Command::new(prog)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("SCOUT_ACCESS_TOKEN", &g.access)
        .process_group(0)
        .spawn();
    let mut group = match child {
        Ok(child) => Group { child, grace: o.kill_grace },
        Err(e) => {
            log(&format!("cannot start command: {e}"));
            return 127;
        }
    };
    monitor(c, o, &mut group.child, &mut g, held)
}

fn monitor(c: &Client, o: &Options, child: &mut Child, g: &mut Grant, held: &mut Vec<(String, String)>) -> i32 {
    let (mut next_poll, mut failed, mut renew_dead) = (Instant::now() + o.poll_every, 0u32, false);
    loop {
        if let Ok(Some(st)) = child.try_wait() {
            return st.code().unwrap_or(1);
        }
        if let Some(code) = interrupted() {
            return code;
        }
        std::thread::sleep(Duration::from_millis(100));
        let now = (c.clock)();
        if !renew_dead && now + o.renew_margin >= g.access_expires {
            match c.renew_recoverable(g, 5, Duration::from_millis(500)) {
                Ok(n) => {
                    log(&format!("renewed to generation {}", n.generation));
                    held.push(("access".into(), n.access.clone()));
                    if let Some(h) = held.iter_mut().find(|(k, _)| k == "refresh") {
                        h.1 = n.refresh.clone();
                    }
                    *g = n;
                }
                Err(e) if e.transient() => log(&format!("renewal not completed yet ({e}); the same operation is retried")),
                Err(e) => {
                    log(&format!("renewal failed permanently ({e}); the capability needs fresh consent"));
                    renew_dead = true;
                }
            }
        }
        let mut reason = None;
        if Instant::now() >= next_poll {
            next_poll = Instant::now() + o.poll_every;
            match c.status() {
                Ok(s) if TERMINAL.contains(&s.state.as_str()) => reason = Some(format!("session {}", s.state)),
                Ok(_) => failed = 0,
                Err(CallErr::Api(404 | 410, _)) => reason = Some("session closed".to_string()),
                Err(_) => {
                    failed += 1;
                    if failed >= o.max_failed_polls {
                        reason = Some(format!("{failed} failed status polls"));
                    }
                }
            }
        }
        if now >= c.deadline {
            reason = Some("session deadline reached".into());
        }
        if renew_dead && now >= g.access_expires {
            reason = Some("access token expired and cannot be renewed".into());
        }
        if let Some(r) = reason {
            log(&format!("stopping command: {r}"));
            return 75;
        }
    }
}

/// The child's process group: whatever way the supervisor leaves, every member is stopped.
struct Group {
    child: Child,
    grace: Duration,
}

impl Drop for Group {
    fn drop(&mut self) {
        terminate(&mut self.child, self.grace);
    }
}

/// SIGTERM to the whole group, SIGKILL after the grace period if any member is left (even when the
/// leader already exited), and reap the leader.
fn terminate(child: &mut Child, grace: Duration) {
    let pg = Pid::from_raw(child.id() as i32);
    let _ = killpg(pg, Signal::SIGTERM);
    let end = Instant::now() + grace;
    while Instant::now() < end {
        let _ = child.try_wait();
        if killpg(pg, None) == Err(Errno::ESRCH) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = killpg(pg, Signal::SIGKILL);
    let _ = child.wait();
}
