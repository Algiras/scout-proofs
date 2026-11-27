// SPDX-License-Identifier: Apache-2.0

//! What the real binaries write to stdout, stderr and the store file during a full session, and what the workload sees.
mod support;

use scout_runner::Client;
use scout_wire::{b64, unb64};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use support::*;

#[test]
fn no_secret_reaches_output_or_the_store_and_the_workload_environment_is_minimal() {
    let live = Live::start(8);
    let mut req = Client::with_ureq(&live.broker);
    req.create_unbound(3600).unwrap();
    // The runner gets the session id and secret through its environment, not its command line.
    let mut run = Proc::spawn(
        &live.dir,
        "run",
        "scout-run",
        &["--broker", &live.broker, "--auto-consent", "true", "--poll-every", "1", "--", "/usr/bin/env"],
        &[("SCOUT_SESSION", &req.session), ("SCOUT_SECRET", &req.secret)],
    );
    assert_eq!(run.wait(Duration::from_secs(40)), Some(0), "{}", run.text());

    // The workload printed its own environment to the runner's stdout.
    let env_out = std::fs::read_to_string(&run.out).unwrap();
    let vars: Vec<(&str, &str)> = env_out.lines().filter_map(|l| l.split_once('=')).collect();
    let names: BTreeSet<&str> = vars.iter().map(|v| v.0).collect();
    assert_eq!(names, BTreeSet::from(["PATH", "SCOUT_ACCESS_TOKEN"]), "workload environment: {env_out}");
    let access = vars.iter().find(|v| v.0 == "SCOUT_ACCESS_TOKEN").unwrap().1.to_string();
    assert!(access.starts_with("at_"));

    let run_err = std::fs::read_to_string(&run.err).unwrap();
    let mut written = live.all_output();
    written.push_str(&run_err);
    let store_raw = std::fs::read(&live.store).unwrap();
    let mut store_text = String::from_utf8_lossy(&store_raw).into_owned();
    let map: std::collections::BTreeMap<String, String> = serde_json::from_slice(&store_raw).unwrap();
    for v in map.values() {
        store_text.push_str(&String::from_utf8_lossy(&unb64(v).unwrap()));
    }
    assert!(!live.procs[1].text().is_empty() && !run_err.is_empty(), "nothing was captured");
    for (name, secret) in [
        ("access token", access.as_str()),
        ("session secret", req.secret.as_str()),
        ("client secret", LIVE_CLIENT_SECRET),
        ("commitment key", LIVE_COMMIT_KEY),
    ] {
        for needle in [secret.to_string(), b64(secret.as_bytes())] {
            assert!(!written.contains(&needle), "{name} appears in process output");
            assert!(!store_text.contains(&needle), "{name} appears in the store file");
        }
    }
    for text in [&written, &store_text] {
        for p in ["rt_", "at_"] {
            let leaked = text.match_indices(p).any(|(i, _)| text[i + 3..].chars().take_while(char::is_ascii_hexdigit).count() >= 32);
            assert!(!leaked, "a provider token value ({p}...) was written");
        }
    }
    assert!(!run.text().contains(&req.session) || run_err.contains("consent URL"), "only the consent URL may name the session");
}

#[test]
fn access_log_escapes_control_characters() {
    let live = Live::start(8);
    let addr = live.broker.trim_start_matches("http://").to_string();
    let mut s = TcpStream::connect(&addr).unwrap();
    s.write_all(b"GET /\x1b[31mred\x07\x7f HTTP/1.1\r\n\r\n").unwrap();
    let mut out = vec![];
    let _ = s.read_to_end(&mut out);
    std::thread::sleep(Duration::from_millis(300));
    let log = std::fs::read(&live.procs[1].err).unwrap();
    assert!(!log.iter().any(|b| *b == 0x1b || *b == 0x07 || *b == 0x7f), "raw control bytes in the access log");
    assert!(String::from_utf8_lossy(&log).contains("\\u{1b}"), "{}", String::from_utf8_lossy(&log));
}
