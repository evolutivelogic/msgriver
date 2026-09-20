//! MsgRiver provider connectors.
//!
//! This crate will define the closed driver boundary and exact HTTP policy: a
//! deterministic fake driver, the exact loopback ntfy byte contract, outcome
//! classification, and the timeout, body, TLS, proxy, redirect, and SSRF
//! policies. It may use Tokio/Hyper/Rustls but must never depend on the store or
//! any application code.
//!
//! No product behavior exists in this scaffold layer.

#![forbid(unsafe_code)]

pub mod driver;
pub mod ntfy;
pub mod retry_after;
pub mod whatsapp;
