// SPDX-License-Identifier: Apache-2.0

//! Teardown and closure ordering (T1, T2, T4, T6).
use crate::Reject;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Td {
    /// Runner signing key still retained.
    pub key: bool,
    pub closed: bool,
    pub deleted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Ev {
    /// A token was submitted for revocation; `delivered` says its keyed digest
    /// was recorded when it was sealed for this session.
    Gate {
        delivered: bool,
    },
    Close,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    None,
    /// The client authentication may be used to revoke this token.
    Attempt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Outcome {
    Ack,
    Unsupported,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reported {
    Revoked,
    Unsupported,
    Failed,
    Unknown,
}

impl Td {
    pub fn new() -> Td {
        Td { key: true, closed: false, deleted: false }
    }
}

impl Default for Td {
    fn default() -> Self {
        Td::new()
    }
}

pub fn step(t: &Td, e: Ev) -> Result<(Td, Out), Reject> {
    match e {
        #[cfg(not(feature = "broken-variants"))]
        Ev::Gate { delivered } => {
            if !t.key {
                return Err(Reject::NoKey);
            }
            if !delivered {
                return Err(Reject::NotDelivered);
            }
            Ok((*t, Out::Attempt))
        }
        #[cfg(feature = "broken-variants")]
        Ev::Gate { .. } => Ok((*t, Out::Attempt)), // broken T1 and T6
        Ev::Close => Ok((Td { closed: true, ..*t }, Out::None)),
        Ev::Delete if !t.closed => Err(Reject::NotClosed),
        Ev::Delete => Ok((Td { key: false, closed: true, deleted: true }, Out::None)),
    }
}

/// Only a provider acknowledgement counts as revoked.
pub fn classify(o: Outcome) -> Reported {
    match o {
        Outcome::Ack => Reported::Revoked,
        Outcome::Unsupported => Reported::Unsupported,
        Outcome::Failed => Reported::Failed,
        Outcome::Unknown => Reported::Unknown,
    }
}
