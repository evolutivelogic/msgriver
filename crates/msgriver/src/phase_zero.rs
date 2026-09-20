//! Test-only private Phase 0B composition seam.
//!
//! The typed state below is fixture authority, not product behavior.  It gives
//! the frozen RED an independently inspectable durable boundary before the
//! reference-loop factory is allowed to acquire an implementation.

pub(crate) mod deployment;
pub(crate) mod reference_loop;
pub(crate) mod reference_loop_port;
