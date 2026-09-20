//! Typed catalog declarations and generated frozen-descriptor materialization.
//!
//! This module contains no operation records, routing, serialization, stable
//! API errors, or client behavior.  The closed vocabulary is generated from
//! the frozen catalog solely so unchanged RED cases can name their expected
//! contract values once real materialization is implemented.

use core::fmt;

use crate::{
    Authorization, Binding, CodecId, HttpMethod, Idempotency, OneTimeMode, OperationId, Risk,
};

/// A complete frozen operation descriptor. It is catalog metadata only, not a
/// route, a typed codec, an authorization decision, or executable behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationDescriptor {
    pub id: OperationId,
    pub method: HttpMethod,
    pub path: &'static str,
    pub bindings: &'static [Binding],
    pub authorization: Authorization,
    pub request_codec: CodecId,
    pub response_codec: Option<CodecId>,
    pub idempotency: Idempotency,
    pub risk: Risk,
    pub one_time_mode: Option<OneTimeMode>,
}

/// Private-to-the-product scaffold vocabulary used only to classify RED tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum ProtocolFrontier {
    CatalogMaterialize,
}

impl ProtocolFrontier {
    #[doc(hidden)]
    pub const fn label(self) -> &'static str {
        "protocol_catalog_materialize"
    }
}

/// Non-stable scaffold error.  It must never become an HTTP or CLI error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct ProtocolError {
    frontier: ProtocolFrontier,
}

impl ProtocolError {
    #[doc(hidden)]
    pub const fn scaffold_frontier(&self) -> Option<ProtocolFrontier> {
        Some(self.frontier)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol scaffold frontier `{}`", self.frontier.label())
    }
}

impl std::error::Error for ProtocolError {}

/// Materialize the immutable descriptor catalog generated from the canonical
/// operation source. Callers receive metadata only; route selection, codecs,
/// authorization, and all service behavior remain separate frontiers.
pub fn operation_catalog() -> Result<&'static [OperationDescriptor], ProtocolError> {
    Ok(crate::catalog_materialized::OPERATION_CATALOG)
}
