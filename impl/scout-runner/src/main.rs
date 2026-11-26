// SPDX-License-Identifier: CC-BY-4.0

#![forbid(unsafe_code)]

use scout_runner::{run, Client, Options};
use scout_wire::{arg, arg_or};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command: Vec<String> = args.iter().position(|a| a == "--").map(|i| args[i + 1..].to_vec()).unwrap_or_default();
    let Some(broker) = arg("broker") else {
        eprintln!(
            "usage: scout-run --broker URL [--principal P] [--ttl S] [--auto-consent true] [--session ID --secret S] -- COMMAND [ARGS...]"
        );
        std::process::exit(64);
    };
    let secs = |n: &str, d: &str| Duration::from_secs(arg_or(n, d).parse().unwrap_or(1));
    let defaults = Options::default();
    let o = Options {
        principal: arg_or("principal", &defaults.principal),
        ttl: arg_or("ttl", "3600").parse().unwrap_or(3600),
        auto_consent: arg_or("auto-consent", "false") == "true",
        bind: arg("session").zip(arg("secret")),
        command,
        poll_every: secs("poll-every", "2"),
        renew_margin: arg_or("renew-margin", "30").parse().unwrap_or(30),
        ..defaults
    };
    let mut c = Client::with_ureq(&broker);
    std::process::exit(run(&mut c, &o));
}
