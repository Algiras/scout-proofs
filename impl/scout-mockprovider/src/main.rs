// SPDX-License-Identifier: CC-BY-4.0

#![forbid(unsafe_code)]

use scout_mockprovider::{start, Config};
use scout_wire::{arg, arg_or};

fn main() {
    let secret = arg("client-secret").unwrap_or_else(|| {
        eprintln!("mockprovider: --client-secret (or SCOUT_CLIENT_SECRET) is required");
        std::process::exit(2);
    });
    let cfg = Config {
        client_id: arg_or("client-id", "scout-demo"),
        client_secret: secret,
        auto_approve: arg_or("auto-approve", "false") == "true",
        access_ttl: arg_or("access-ttl", "3600").parse().unwrap_or(3600),
    };
    let front = arg_or("listen", "127.0.0.1:9000");
    let _servers = match arg("backchannel-listen") {
        Some(back) => {
            let (f, b) = scout_mockprovider::start_split(&front, &back, cfg).expect("listen");
            eprintln!("mockprovider listening on {} (browser/resource) and {} (token/revoke)", f.addr, b.addr);
            vec![f, b]
        }
        None => {
            let s = start(&front, cfg).expect("listen");
            eprintln!("mockprovider listening on {}", s.addr);
            vec![s]
        }
    };
    loop {
        std::thread::park();
    }
}
