// SPDX-License-Identifier: CC-BY-4.0

//! Demo workload: calls a protected URL with the access token from its environment.
#![forbid(unsafe_code)]

use scout_wire::http::{Transport, Ureq};

fn main() {
    let (Some(url), Ok(tok)) = (std::env::args().nth(1), std::env::var("SCOUT_ACCESS_TOKEN")) else {
        eprintln!("usage: SCOUT_ACCESS_TOKEN=... scout-whoami URL [SLEEP_SECONDS]");
        std::process::exit(64);
    };
    let auth = format!("Bearer {tok}");
    match (Ureq { redirects: 0 }).call("GET", &url, &[("Authorization", auth.as_str())], &[]) {
        Ok((200, body)) => {
            println!("whoami: {}", String::from_utf8_lossy(&body));
            // Optionally stay alive so the runner has time to renew.
            if let Some(n) = std::env::args().nth(2).and_then(|n| n.parse().ok()) {
                std::thread::sleep(std::time::Duration::from_secs(n));
            }
        }
        Ok((s, body)) => {
            eprintln!("whoami: HTTP {s} {}", String::from_utf8_lossy(&body));
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("whoami: {e}");
            std::process::exit(1);
        }
    }
}
