//! MsgRiver protocol surface.
//!
//! This crate will own the frozen operation catalog, strict JSON and nesting
//! rules, every typed wire codec, the stable API error mapping and message
//! templates, pagination, operation-catalog parsing, route specificity, and the
//! generated operation-set closure. It depends only on `msgriver-core` and must
//! never reach the store, filesystem, provider, or server.
//!
//! No product behavior exists in this scaffold layer.

#![forbid(unsafe_code)]

pub mod catalog;
mod catalog_generated;
mod catalog_materialized;
pub mod json;
pub mod path;

pub use catalog::{OperationDescriptor, ProtocolError, ProtocolFrontier, operation_catalog};
pub use catalog_generated::{
    Authorization, Binding, CodecId, HttpMethod, Idempotency, OneTimeMode, OperationId, Risk,
};
pub use json::{JsonError, JsonFrontier, StrictJsonReject, StrictJsonResult, strict_json_value};
pub use path::{
    PathDecodeResult, PathError, PathFrontier, PathReject, PathSegment, decode_path_segment,
};
