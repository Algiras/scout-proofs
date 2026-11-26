// SPDX-License-Identifier: Apache-2.0

//! The SCOUT broker: HTTP shell around `scout-core`.
#![forbid(unsafe_code)]

pub mod provider;
pub mod records;
pub mod renewal;
pub mod server;
pub mod store;
