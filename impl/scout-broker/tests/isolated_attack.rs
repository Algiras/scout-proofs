// SPDX-License-Identifier: Apache-2.0

//! The attack scenario of `isolated/docker-compose.yml` without Docker: the real broker, provider, victim and
//! attacker binaries as child processes on loopback. Network isolation cannot be checked here (every port is
//! reachable from every process), so the attacker is not given a back channel address and skips that one attack;
//! the compose run is what covers it.
mod support;

use scout_wire::unb64;
use std::time::Duration;
use support::*;

fn token_like(text: &str) -> Vec<String> {
    let mut out = vec![];
    for prefix in ["at_", "rt_"] {
        for (i, _) in text.match_indices(prefix) {
            let hex: String = text[i + 3..].chars().take_while(char::is_ascii_hexdigit).collect();
            if hex.len() >= 32 {
                out.push(format!("{prefix}{hex}"));
            }
        }
    }
    out
}

fn start_actors(live: &Live, shared: &std::path::Path, back: Option<&str>) -> (Proc, Proc) {
    let sh = shared.to_str().unwrap();
    let victim = Proc::spawn(
        &live.dir,
        "victim",
        "scout-victim",
        &["--broker", &live.broker, "--provider-front", &live.front, "--shared", sh, "--run-seconds", "20"],
        &[],
    );
    let mut args = vec!["--broker", &live.broker, "--provider-front", &live.front, "--shared", sh, "--victim-timeout", "90"];
    if let Some(b) = back {
        args.extend(["--provider-back", b]);
    }
    let attacker = Proc::spawn(&live.dir, "attacker", "scout-attacker", &args, &[]);
    (victim, attacker)
}

#[test]
fn every_attack_is_refused_and_the_victim_finishes() {
    let live = Live::start(8);
    let shared = live.dir.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    let (mut victim, mut attacker) = start_actors(&live, &shared, None);
    let code = attacker.wait(Duration::from_secs(120));
    let out = attacker.text();
    println!("{out}");
    assert_eq!(code, Some(0), "attacker output:\n{out}");
    assert!(out.contains("ATTACKS REFUSED 9/9"), "{out}");
    assert!(out.contains("SKIP reach-provider-back-channel-directly"), "{out}");
    assert!(!out.contains("FAIL"), "{out}");
    assert_eq!(victim.wait(Duration::from_secs(60)), Some(0), "victim output:\n{}", victim.text());
    assert_eq!(std::fs::read_to_string(shared.join("victim.result")).unwrap(), "ok");

    let stats = live.stats();
    let fams = stats["families"].as_array().unwrap();
    assert_eq!(fams.len(), 2);
    assert!(fams.iter().all(|f| f["revoked"] == true), "both sessions tore down: {stats}");
    assert!(fams.iter().all(|f| f["refreshCalls"].as_u64().unwrap() >= 1));

    let mut seen = live.all_output();
    seen.push_str(&victim.text());
    seen.push_str(&out);
    assert_eq!(token_like(&seen), Vec::<String>::new(), "a token value reached a log");
    let store = std::fs::read(&live.store).unwrap();
    let store = String::from_utf8_lossy(&store).into_owned();
    let map: std::collections::BTreeMap<String, String> = serde_json::from_str(&store).unwrap();
    for v in map.values() {
        assert!(token_like(&String::from_utf8_lossy(&unb64(v).unwrap())).is_empty(), "a token value is in the store");
    }
}

#[test]
fn the_attacker_reports_failure_when_an_attack_succeeds() {
    // Here the provider's back channel is deliberately handed to the attacker as reachable: it must notice.
    let live = Live::start(8);
    let shared = live.dir.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    let back = live.back.trim_start_matches("http://").to_string();
    let (mut victim, mut attacker) = start_actors(&live, &shared, Some(&back));
    assert_eq!(attacker.wait(Duration::from_secs(120)), Some(1));
    let out = attacker.text();
    assert!(out.contains("FAIL reach-provider-back-channel-directly"), "{out}");
    assert!(out.contains("ATTACKS REFUSED 9/10"), "{out}");
    assert_eq!(victim.wait(Duration::from_secs(60)), Some(0));
}
