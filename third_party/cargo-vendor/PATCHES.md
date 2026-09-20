# Local Cargo patches

This directory contains two deliberately narrow local patches required to keep
the SQLite store's required dependency versions buildable on MsgRiver's Rust
1.89 MSRV.

## Provenance

| Crate | Version | crates.io archive SHA-256 |
| --- | --- | --- |
| `rusqlite` | `0.40.1` | `11438310b19e3109b6446c33d1ed5e889428cf2e278407bc7896bc4aaea43323` |
| `libsqlite3-sys` | `0.38.1` | `f6c19a05435c21ac299d71b6a9c13db3e3f47c520517d58990a462a1397a61db` |

Both copies were produced with `cargo vendor` from those archive versions.
Their upstream `LICENSE` files remain beside the source.

## Delta

The only source changes replace uses of unstable `cfg_select!` with their
equivalent stable `#[cfg]` branches:

- `libsqlite3-sys/build.rs`: bundled binding generation and generated-binding
  output (`buildtime_bindgen` and `loadable_extension`).
- `rusqlite/src/{raw_statement,lib,statement,error,inner_connection}.rs`:
  the seven conditional branches for `unlock_notify`, `modern_sqlite`,
  `extra_check`, and Unix path conversion.

No public dependency version, enabled feature, SQLite C source, or runtime
behavior is intentionally changed. The exact `rusqlite = 0.40.1` requirement
and its `bundled` feature remain authoritative in the workspace manifest.

Remove both `[patch.crates-io]` entries once the same dependency versions ship
stable `cfg_select!`-free sources, after re-running the Rust 1.89 and 1.96
workspace gates.
