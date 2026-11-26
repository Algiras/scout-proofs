// SPDX-License-Identifier: CC-BY-4.0

//! Pure protocol logic. Tokens, commitments, ciphertexts and operation ids are
//! opaque nonzero `Id`s chosen by the caller; 0 always means "none".
#![forbid(unsafe_code)]

pub mod delivery;
#[cfg(test)]
mod explore;
#[cfg(any(kani, test))]
pub mod ghost;
#[cfg(kani)]
mod proofs;
pub mod renewal;
pub mod session;
pub mod teardown;

pub type Id = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Event not allowed in this state (including any event on a terminal state).
    State,
    /// Consent before the runner keys are pinned.
    NotBound,
    /// A second principal tried to consent.
    Principal,
    /// Sealing key differs from the pinned key, or a zero id was supplied.
    Key,
    /// Delivery is blocked (revoked or closed).
    Blocked,
    /// The shared delivery/renewal record is closed.
    Closed,
    /// Ambiguous earlier outcome: only fresh consent can restore the capability.
    Recovery,
    /// Presented generation is not the committed one.
    Stale,
    /// Presented token does not match the committed commitment.
    Commitment,
    /// A different operation holds the reservation.
    Competing,
    /// The same operation is still executing.
    InProgress,
    /// Session deadline passed.
    Expired,
    /// Saved reply is past its recovery window.
    Lapsed,
    /// Commit or exchange without a live reservation.
    NoClaim,
    /// Token was not delivered in this session.
    NotDelivered,
    /// Runner key no longer retained.
    NoKey,
    /// Delete before close.
    NotClosed,
}

/// Seconds a saved renewal reply stays retrievable.
pub const RECOVERY_WINDOW: u64 = 600;
