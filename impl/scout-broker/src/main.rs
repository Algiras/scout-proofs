// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use scout_broker::provider::Provider;
use scout_broker::renewal::Renewer;
use scout_broker::server::{Broker, Config};
use scout_broker::store::{MemStore, Store};
use scout_wire::http::{serve, Ureq};
use scout_wire::{arg, arg_or, now_secs};
use std::sync::Arc;

fn need(name: &str) -> String {
    arg(name).unwrap_or_else(|| {
        eprintln!("scoutd: --{name} (or SCOUT_{}) is required", name.to_uppercase().replace('-', "_"));
        std::process::exit(2);
    })
}

fn main() {
    let listen = arg_or("listen", "127.0.0.1:8080");
    let public_base = arg_or("public-base-url", &format!("http://{listen}"));
    let authority =
        arg("authority").unwrap_or_else(|| public_base.split("://").nth(1).unwrap_or(&public_base).trim_end_matches('/').to_string());
    let client_secret = need("client-secret");
    let commit_key = need("commit-key");
    if commit_key == client_secret || commit_key.len() < 16 {
        eprintln!("scoutd: the commitment key must be at least 16 bytes and differ from the client secret");
        std::process::exit(2);
    }
    let store: Arc<dyn Store> = match arg("store-file") {
        Some(p) => Arc::new(MemStore::open_file(p).unwrap_or_else(|e| {
            eprintln!("scoutd: {e}");
            std::process::exit(1);
        })),
        None => Arc::new(MemStore::new()),
    };
    let client_id = arg_or("client-id", "scout-demo");
    let provider = Provider {
        auth_url: need("provider-auth-url"),
        token_url: need("provider-token-url"),
        revoke_url: arg("provider-revoke-url").filter(|u| !u.is_empty()),
        client_id: client_id.clone(),
        client_secret,
        scope: arg_or("scope", "read"),
        transport: Arc::new(Ureq { redirects: 0 }),
    };
    let renewer = Renewer::new(store.clone(), commit_key.into_bytes(), &client_id, Arc::new(now_secs));
    let cfg = Config {
        authority,
        public_base,
        default_ttl: arg_or("default-ttl", "3600").parse().unwrap_or(3600),
        max_ttl: arg_or("max-ttl", "86400").parse().unwrap_or(86400),
    };
    let broker = Arc::new(Broker { cfg, store, renewer, provider });
    let srv = serve(&listen, broker.handler()).unwrap_or_else(|e| {
        eprintln!("scoutd: cannot listen on {listen}: {e}");
        std::process::exit(1);
    });
    eprintln!("scoutd listening on {}", srv.addr);
    loop {
        std::thread::park();
    }
}
