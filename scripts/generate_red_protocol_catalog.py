#!/usr/bin/env python3
"""Generate the additive protocol/catalog RED checkpoint from frozen TOML.

This generator deliberately reads ``specs/operations.toml`` directly.  It
emits test expectations and review inventory, but never a working catalog: the
only production entry point remains the explicit scaffold seam in
``msgriver-protocol``.  ``--check`` makes authored artifacts immutable between
authoring checkpoints.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = ROOT / "specs/operations.toml"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _ident(value: str) -> str:
    words = [word for word in re.split(r"[^A-Za-z0-9]+", value) if word]
    result = "".join(word[:1].upper() + word[1:].lower() for word in words)
    if not result or result[0].isdigit():
        raise ValueError(f"cannot make Rust identifier from {value!r}")
    return result


def _symbol(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _rust(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _rustfmt(source: str) -> str:
    """Format generated Rust with the workspace-pinned formatter."""
    completed = subprocess.run(
        ["rustfmt", "--edition", "2024"],
        input=source,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(f"rustfmt failed: {completed.stderr.strip()}")
    return completed.stdout


def _load_operations() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = tomllib.loads(OPERATIONS.read_text(encoding="utf-8"))
    operations = data.get("operation")
    if not isinstance(operations, list) or not all(isinstance(op, dict) for op in operations):
        raise ValueError("operations.toml must contain [[operation]] records")
    return data, operations


def _codec_refs(operations: list[dict[str, Any]]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for op in operations:
        for direction, field in (("request", "request_codec"), ("response", "response_codec")):
            codec = op[field]
            if codec != "none":
                refs.append({"operation_id": op["id"], "direction": direction, "codec_id": codec})
    return refs


def _enum(name: str, values: list[str]) -> str:
    variants = [_ident(value) for value in values]
    if len(set(variants)) != len(variants):
        raise ValueError(f"{name} identifiers collide")
    lines = [
        "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]",
        f"pub enum {name} {{",
    ]
    lines.extend(f"    {variant}," for variant in variants)
    lines.append("}")
    lines.append("")
    lines.append(f"impl {name} {{")
    lines.append("    #[doc(hidden)]")
    lines.append("    pub const fn as_str(self) -> &'static str {")
    lines.append("        match self {")
    lines.extend(f"            Self::{variant} => {_rust(value)}," for value, variant in zip(values, variants))
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


def _render_types(operations: list[dict[str, Any]]) -> str:
    op_ids = [str(op["id"]) for op in operations]
    codecs = sorted({str(op[field]) for op in operations for field in ("request_codec", "response_codec")})
    methods = sorted({str(op["method"]) for op in operations})
    bindings = sorted({str(binding) for op in operations for binding in op["bindings"]})
    authorizations = sorted({str(op["authorization"]) for op in operations})
    idempotencies = sorted({str(op["idempotency"]) for op in operations})
    risks = sorted({str(op["risk"]) for op in operations})
    one_time_modes = sorted({str(op["one_time_mode"]) for op in operations if "one_time_mode" in op})
    return """//! Generated closed identifier vocabularies for the protocol catalog. DO NOT EDIT.
//!
//! Regenerated from `specs/operations.toml` by
//! `scripts/generate_red_protocol_catalog.py`. They are used by the generated
//! descriptor catalog but do not implement a wire protocol.

""" + "\n\n".join((
        _enum("OperationId", op_ids), _enum("CodecId", codecs), _enum("HttpMethod", methods),
        _enum("Binding", bindings), _enum("Authorization", authorizations),
        _enum("Idempotency", idempotencies), _enum("Risk", risks), _enum("OneTimeMode", one_time_modes),
    )) + "\n"


def _descriptor(op: dict[str, Any]) -> str:
    binding = ", ".join(f"Binding::{_ident(value)}" for value in op["bindings"])
    response = "None" if op["response_codec"] == "none" else f"Some(CodecId::{_ident(op['response_codec'])})"
    one_time = op.get("one_time_mode")
    one_time_expr = "None" if one_time is None else f"Some(OneTimeMode::{_ident(one_time)})"
    return "OperationDescriptor { " + ", ".join((
        f"id: OperationId::{_ident(op['id'])}",
        f"method: HttpMethod::{_ident(op['method'])}",
        f"path: {_rust(op['path'])}",
        f"bindings: &[{binding}]",
        f"authorization: Authorization::{_ident(op['authorization'])}",
        f"request_codec: CodecId::{_ident(op['request_codec'])}",
        f"response_codec: {response}",
        f"idempotency: Idempotency::{_ident(op['idempotency'])}",
        f"risk: Risk::{_ident(op['risk'])}",
        f"one_time_mode: {one_time_expr}",
    )) + " }"


def _render_catalog(operations: list[dict[str, Any]]) -> str:
    descriptors = ",\n    ".join(_descriptor(operation) for operation in operations)
    return """//! Generated exact operation descriptors. DO NOT EDIT.
//!
//! Regenerated from `specs/operations.toml` by
//! `scripts/generate_red_protocol_catalog.py`. This is catalog metadata only:
//! it selects no route, parses no codec, and performs no authorization or I/O.

use crate::{
    Authorization, Binding, CodecId, HttpMethod, Idempotency, OneTimeMode,
    OperationDescriptor, OperationId, Risk,
};

pub(crate) static OPERATION_CATALOG: &[OperationDescriptor] = &[
    """ + descriptors + """
];
"""


def _render_cases(operations: list[dict[str, Any]], source_digest: str, fixture_digest: str) -> str:
    refs = _codec_refs(operations)
    refs_text = ",\n    ".join(
        f"CodecReference {{ operation_id: OperationId::{_ident(ref['operation_id'])}, direction: {_rust(ref['direction'])}, codec_id: CodecId::{_ident(ref['codec_id'])} }}"
        for ref in refs
    )
    out = """//! Generated protocol/catalog RED cases. DO NOT EDIT.
//!
//! The expectations are generated from the frozen catalog, never from a Rust
//! descriptor.  Every case calls the real protocol seam.  Until materialization
//! is implemented, that seam reports the registered scaffold frontier and the
//! test fails intentionally as `behavior_red`.

use msgriver_protocol::{
    operation_catalog, Authorization, Binding, CodecId, HttpMethod, Idempotency,
    OneTimeMode, OperationDescriptor, OperationId, ProtocolFrontier, Risk,
};
use std::fmt;

const SOURCE_DIGEST: &str = """ + _rust(source_digest) + ";\n" + "const FIXTURE_DIGEST: &str = " + _rust(fixture_digest) + ";\n\n" + """
#[derive(Debug)]
enum CatalogCaseError {
    BehaviorRed { case_id: &'static str },
    Mismatch { case_id: &'static str, detail: String },
}

impl fmt::Display for CatalogCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BehaviorRed { case_id } => write!(
                f,
                "{case_id}: behavior missing — terminated at RED frontier `protocol_catalog_materialize`"
            ),
            Self::Mismatch { case_id, detail } => write!(f, "{case_id}: observable mismatch — {detail}"),
        }
    }
}

impl std::error::Error for CatalogCaseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CodecReference {
    operation_id: OperationId,
    direction: &'static str,
    codec_id: CodecId,
}

fn live_catalog(case_id: &'static str) -> Result<&'static [OperationDescriptor], CatalogCaseError> {
    match operation_catalog() {
        Ok(catalog) => Ok(catalog),
        Err(error) if error.scaffold_frontier() == Some(ProtocolFrontier::CatalogMaterialize) => {
            Err(CatalogCaseError::BehaviorRed { case_id })
        }
        Err(error) => Err(CatalogCaseError::Mismatch {
            case_id,
            detail: format!("unexpected protocol error: {error}"),
        }),
    }
}

fn operation_case(case_id: &'static str, expected: OperationDescriptor) -> Result<(), CatalogCaseError> {
    let catalog = live_catalog(case_id)?;
    let Some(actual) = catalog.iter().find(|item| item.id == expected.id) else {
        return Err(CatalogCaseError::Mismatch { case_id, detail: format!("missing operation {}", expected.id.as_str()) });
    };
    if actual != &expected {
        return Err(CatalogCaseError::Mismatch { case_id, detail: format!("descriptor mismatch for {}", expected.id.as_str()) });
    }
    Ok(())
}

fn catalog_references(catalog: &[OperationDescriptor]) -> Vec<CodecReference> {
    let mut refs = Vec::new();
    for descriptor in catalog {
        if descriptor.request_codec != CodecId::None {
            refs.push(CodecReference { operation_id: descriptor.id, direction: "request", codec_id: descriptor.request_codec });
        }
        if let Some(codec_id) = descriptor.response_codec {
            refs.push(CodecReference { operation_id: descriptor.id, direction: "response", codec_id });
        }
    }
    refs.sort();
    refs
}

"""
    for op in operations:
        case_id = f"PROTO-CATALOG-OP-{op['id'].upper()}"
        out += f"#[test]\nfn proto_catalog_op_{_symbol(op['id'])}() -> Result<(), CatalogCaseError> {{\n    operation_case({_rust(case_id)}, {_descriptor(op)})\n}}\n\n"
    ids = ", ".join(f"OperationId::{_ident(op['id'])}" for op in operations)
    out += """#[test]
fn proto_catalog_operation_set() -> Result<(), CatalogCaseError> {
    let case_id = "PROTO-CATALOG-OPERATION-SET";
    let catalog = live_catalog(case_id)?;
    let actual: Vec<OperationId> = catalog.iter().map(|item| item.id).collect();
    let expected = [""" + ids + """ ];
    if actual != expected {
        return Err(CatalogCaseError::Mismatch { case_id, detail: "operation ID set or order differs".into() });
    }
    Ok(())
}

#[test]
fn proto_catalog_codec_references() -> Result<(), CatalogCaseError> {
    let case_id = "PROTO-CATALOG-CODEC-REFERENCES";
    let catalog = live_catalog(case_id)?;
    let mut expected = vec![
    """ + refs_text + """
    ];
    expected.sort();
    if catalog_references(catalog) != expected {
        return Err(CatalogCaseError::Mismatch { case_id, detail: "codec reference closure differs".into() });
    }
    if SOURCE_DIGEST.is_empty() || FIXTURE_DIGEST.is_empty() {
        return Err(CatalogCaseError::Mismatch { case_id, detail: "unbound generated input digest".into() });
    }
    Ok(())
}
"""
    return out


def _render_fixture(data: dict[str, Any], operations: list[dict[str, Any]], source_digest: str) -> str:
    payload = {
        "format": "msgriver/protocol-catalog-oracle/v1",
        "operations_source_sha256": source_digest,
        "catalog_version": data["catalog_version"],
        "operation_count": len(operations),
        "codec_count": len({ref["codec_id"] for ref in _codec_refs(operations)}),
        "codec_reference_count": len(_codec_refs(operations)),
        "operations": operations,
        "codec_references": _codec_refs(operations),
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _render_manifest(operations: list[dict[str, Any]], source_digest: str, fixture_digest: str) -> str:
    rows: list[str] = [
        "format = \"msgriver/protocol-catalog-cases/v1\"",
        "suite_state = \"authoring-partial\"",
        "catalog_source = \"specs/operations.toml\"",
        f"catalog_source_sha256 = \"{source_digest}\"",
        f"oracle_sha256 = \"{fixture_digest}\"",
        "case_count = 72",
        "operation_case_count = 70",
        "codec_count = 107",
        "codec_reference_count = 133",
        "initial_frontier = \"protocol_catalog_materialize\"",
        "\n# This additive checkpoint earns catalog-reference credit only.  Typed codecs,\n# strict JSON, routes, errors, pagination, and all other protocol work remain pending.",
    ]
    for op in operations:
        case_id = f"PROTO-CATALOG-OP-{op['id'].upper()}"
        rows.extend((
            "\n[[case]]",
            f"case_id = {_toml_string(case_id)}",
            f"test_symbol = {_toml_string('proto_catalog_op_' + _symbol(op['id']))}",
            "kind = \"operation_descriptor\"",
            f"operation_id = {_toml_string(op['id'])}",
            f"final_observable = {_toml_string('materialize the exact frozen descriptor for ' + op['id'])}",
            "evidence_state = \"behavior_red\"",
        ))
    for case_id, symbol, kind, observable in (
        ("PROTO-CATALOG-OPERATION-SET", "proto_catalog_operation_set", "operation_set", "materialize exactly the 70 frozen operation identifiers"),
        ("PROTO-CATALOG-CODEC-REFERENCES", "proto_catalog_codec_references", "codec_reference_closure", "materialize all 107 codec identifiers and 133 directional references"),
    ):
        rows.extend((
            "\n[[case]]", f"case_id = {_toml_string(case_id)}", f"test_symbol = {_toml_string(symbol)}",
            f"kind = {_toml_string(kind)}", f"final_observable = {_toml_string(observable)}", "evidence_state = \"behavior_red\"",
        ))
    return "\n".join(rows) + "\n"


def _render_ledger(operations: list[dict[str, Any]]) -> str:
    rows = [
        "format = \"msgriver/protocol-catalog-ledger/v1\"",
        "suite_state = \"authoring-partial\"",
        "initial_frontier = \"protocol_catalog_materialize\"",
        "initial_frontier_case_count = 72",
    ]
    for op in operations:
        rows.extend(("\n[[entry]]", f"case_id = {_toml_string('PROTO-CATALOG-OP-' + op['id'].upper())}", "frontier = \"protocol_catalog_materialize\""))
    for case_id in ("PROTO-CATALOG-OPERATION-SET", "PROTO-CATALOG-CODEC-REFERENCES"):
        rows.extend(("\n[[entry]]", f"case_id = {_toml_string(case_id)}", "frontier = \"protocol_catalog_materialize\""))
    return "\n".join(rows) + "\n"


def _render_obligations() -> str:
    ownership = tomllib.loads((ROOT / "specs/core-ownership.toml").read_text(encoding="utf-8"))["ownership"]
    ids = [entry["unit_id"] for entry in ownership if entry["classification"] == "layer:protocol"]
    if len(ids) != 455:
        raise ValueError(f"expected 455 protocol ownership leaves, got {len(ids)}")
    lines = [
        "format = \"msgriver/protocol-remaining-obligations/v1\"",
        "source = \"specs/core-ownership.toml\"",
        "protocol_owned_leaf_count = 455",
        "catalog_checkpoint_credit = \"catalog_reference_only\"",
        "\n# Every protocol-owned leaf is retained.  No row receives completeness credit\n# at this checkpoint; later checkpoints replace only its disposition.",
    ]
    for unit_id in ids:
        lines.extend(("\n[[obligation]]", f"unit_id = {_toml_string(unit_id)}", "disposition = \"pending_authoring\""))
    return "\n".join(lines) + "\n"


def artifacts(root: Path) -> dict[Path, str]:
    data, operations = _load_operations()
    source_digest = _digest(OPERATIONS.read_bytes())
    fixture = _render_fixture(data, operations, source_digest)
    fixture_digest = _digest(fixture.encode("utf-8"))
    return {
        root / "crates/msgriver-protocol/src/catalog_generated.rs": _rustfmt(_render_types(operations)),
        root / "crates/msgriver-protocol/src/catalog_materialized.rs": _rustfmt(_render_catalog(operations)),
        root / "crates/msgriver-protocol/tests/red_protocol_catalog/cases.rs": _rustfmt(_render_cases(operations, source_digest, fixture_digest)),
        root / "tests/fixtures/oracles/protocol/catalog/operations.expected.json": fixture,
        root / "reviews/04-red-suite/protocol-catalog/contract-cases.toml": _render_manifest(operations, source_digest, fixture_digest),
        root / "reviews/04-red-suite/protocol-catalog/red-ledger.toml": _render_ledger(operations),
        root / "reviews/04-red-suite/protocol-catalog/remaining-obligations.toml": _render_obligations(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="reject generated artifact drift")
    parser.add_argument("--root", type=Path, default=ROOT, help="artifact root (self-test only)")
    args = parser.parse_args(argv)
    expected = artifacts(args.root)
    drift: list[Path] = []
    for path, content in expected.items():
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            drift.append(path)
            if not args.check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
    if drift and args.check:
        for path in drift:
            print(f"RED-PROTOCOL-CATALOG-GENERATION-DRIFT {path.relative_to(args.root)}", file=sys.stderr)
        return 1
    print(f"GREEN RED-PROTOCOL-CATALOG-GENERATION cases=72 operations=70 codecs=107 refs=133")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
