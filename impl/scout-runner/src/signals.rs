// SPDX-License-Identifier: Apache-2.0

//! SIGTERM, SIGINT and SIGHUP only record that they arrived; the supervision loop acts on it.
#![allow(unsafe_code)]

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::sync::atomic::{AtomicI32, Ordering};

static RECEIVED: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: nix::libc::c_int) {
    RECEIVED.store(sig, Ordering::SeqCst);
}

pub fn install() {
    let act = SigAction::new(SigHandler::Handler(on_signal), SaFlags::empty(), SigSet::empty());
    for sig in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP] {
        // SAFETY: the handler only stores into an atomic, which is async-signal-safe.
        let _ = unsafe { sigaction(sig, &act) };
    }
}

/// The signal number received since `install`, if any.
pub fn received() -> Option<i32> {
    match RECEIVED.load(Ordering::SeqCst) {
        0 => None,
        n => Some(n),
    }
}
