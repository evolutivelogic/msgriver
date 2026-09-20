# Development method

This document is the self-contained public subset of the methodology used to build MsgRiver.

## 1. Intent before behavior

The living specs are the source of truth for intent. Once code exists, tests and runtime evidence
are the source of truth for behavior; any divergence must be reconciled in the same change.

Every substantial specification is generated outside-in, in this order:

1. requirements and non-goals;
2. macro-architecture and trade-offs;
3. planned capabilities;
4. external interface;
5. verifiable contracts and invariants;
6. detailed architecture;
7. persistent data model.

Each layer depends only on earlier layers through stable IDs. Requirements must not be reverse-shaped
by a convenient schema or implementation detail.

## 2. Behavior before implementation

Acceptance and contract tests are written and demonstrated RED before production implementation.
Tests pin observable behavior, not private structure. Structural guard tests are allowed only when
identified as tripwires for an architectural invariant.

The test suite has no public-network egress. Live provider checks are explicit, separate operations
with bounded impact and recorded evidence.

## 3. Independent critical review

Each expensive-to-get-wrong artifact follows three passes:

1. an author creates the artifact;
2. independent model lenses attack assumptions, edge cases, security boundaries, and omissions;
3. the author/adjudicator incorporates accepted findings and records rejected ones with evidence.

Review artifacts are retained under `reviews/`. Agreement is not assumed to mean correctness, and
disagreement is not silently averaged away.

## 4. Rust quality contract

The workspace gate is a single script covering formatting, Clippy with warnings denied, tests,
documentation, and `cargo deny`, all with a pinned toolchain and lockfile.

Additional rules:

- every library crate starts with crate-level mental-model documentation and forbids unsafe code;
- domain errors are typed; `anyhow` is limited to application boundaries;
- production `unwrap`, `panic`, `todo`, `unimplemented`, and `dbg!` are denied;
- every degradation is declared as fail-loud, fail-closed, or advisory degradation;
- secrets use redacted types and never appear in diagnostics;
- authenticated HTTP clients reject redirects by default;
- callers cannot supply provider base URLs;
- clocks, identifiers, transports, and stores have injectable seams for deterministic tests;
- at-least-once external delivery and its duplicate risk are stated honestly.

## 5. Definition of done

An increment is done only when:

- its spec and architecture reviews have no unresolved blocker;
- tests were committed RED before implementation;
- the single Rust gate passes twice;
- security tooling and an adversarial trust-boundary review pass;
- relevant live smoke evidence exists;
- docs and operational handoff match the implemented behavior.
