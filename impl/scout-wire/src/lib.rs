// SPDX-License-Identifier: CC-BY-4.0

//! Shared wire pieces: sealing, signed proofs, commitments, a tiny HTTP server and client.
#![forbid(unsafe_code)]

pub mod commit;
pub mod http;
pub mod proof;
pub mod seal;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand_core::{OsRng, RngCore};

pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| Error("bad base64".into()))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn random_id() -> String {
    hex(&random_bytes::<16>())
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

/// `--name value` / `--name=value`, falling back to env `SCOUT_NAME` (dashes become underscores).
pub fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    let flag = format!("--{name}");
    for (i, a) in args.iter().enumerate() {
        if a == &flag {
            return args.get(i + 1).cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_string());
        }
    }
    std::env::var(format!("SCOUT_{}", name.to_uppercase().replace('-', "_"))).ok()
}

pub fn arg_or(name: &str, default: &str) -> String {
    arg(name).unwrap_or_else(|| default.to_string())
}
