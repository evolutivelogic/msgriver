//! Additive catalog-wide RED contracts.
//!
//! Generated cases are individually nextest-visible.  Their initial failure is
//! the real protocol catalog scaffold, never a test-local fake descriptor.

#![forbid(unsafe_code)]

#[path = "red_protocol_catalog/cases.rs"]
mod cases;
