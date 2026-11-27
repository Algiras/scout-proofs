// SPDX-License-Identifier: Apache-2.0

//! A normal session that renews for a while and deliberately leaks its current refresh token
//! to a shared directory, as if it had been stolen. It must still finish cleanly.
#![forbid(unsafe_code)]

use scout_runner::{Client, Grant};
use scout_wire::http::{Transport, Ureq};
use scout_wire::{arg, arg_or};
use serde_json::json;
use std::path::Path;
use std::time::{Duration, Instant};

fn publish(dir: &Path, name: &str, text: &str) {
    let tmp = dir.join(format!(".{name}.tmp"));
    if std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, dir.join(name))).is_err() {
        eprintln!("scout-victim: cannot write {name} in {}", dir.display());
    }
}

fn leak(dir: &Path, c: &Client, g: &Grant) {
    let v = json!({ "session": c.session, "refresh": g.refresh, "receipt": g.receipt, "generation": g.generation });
    publish(dir, "leak.json", &v.to_string());
}

fn run(dir: &Path) -> Result<(), String> {
    let broker = arg("broker").ok_or("--broker is required")?;
    let front = arg("provider-front").ok_or("--provider-front is required")?;
    let secs: u64 = arg_or("run-seconds", "25").parse().unwrap_or(25);
    let mut c = Client::with_ureq(&broker);
    let mut created = Err("not attempted".to_string());
    for _ in 0..60 {
        created = c.create(3600).map_err(|e| e.to_string());
        if created.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    created?;
    (Ureq { redirects: 5 }).call("GET", &c.consent_url("victim"), &[], &[]).map_err(|e| e.to_string())?;
    let mut g = c.fetch_grant().map_err(|e| format!("grant: {e}"))?;
    leak(dir, &c, &g);
    println!("scout-victim: session active, refresh token leaked");
    let end = Instant::now() + Duration::from_secs(secs);
    let mut renewals = 0u32;
    while Instant::now() < end {
        if (c.clock)() + 5 >= g.access_expires {
            g = c.renew_recoverable(&g, 5, Duration::from_millis(500)).map_err(|e| format!("renewal failed: {e}"))?;
            renewals += 1;
            leak(dir, &c, &g);
        }
        let auth = format!("Bearer {}", g.access);
        let (s, _) = (Ureq { redirects: 0 })
            .call("GET", &format!("{front}/api/whoami"), &[("Authorization", auth.as_str())], &[])
            .map_err(|e| e.to_string())?;
        if s != 200 {
            return Err(format!("the provider rejected the current access token ({s})"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if renewals == 0 {
        return Err("no renewal happened; the scenario is vacuous".into());
    }
    c.revoke(&[("access", &g.access), ("refresh", &g.refresh)]).map_err(|e| format!("revoke: {e}"))?;
    c.finalize().map_err(|e| format!("finalize: {e}"))?;
    println!("scout-victim: finished after {renewals} renewals");
    Ok(())
}

fn main() {
    let dir = std::path::PathBuf::from(arg_or("shared", "/shared"));
    let res = run(&dir);
    match &res {
        Ok(()) => publish(&dir, "victim.result", "ok"),
        Err(e) => {
            eprintln!("scout-victim: {e}");
            publish(&dir, "victim.result", &format!("fail: {e}"));
        }
    }
    std::process::exit(i32::from(res.is_err()));
}
