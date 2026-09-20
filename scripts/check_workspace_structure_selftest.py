#!/usr/bin/env python3
"""Mutation-style self-tests for check_workspace_structure.py.

Every mutation edits a temporary copy of only the structural-gate inputs
(workspace manifests, lockfile, toolchain pin, crate sources, and the tracked
patched vendor tree); the real workspace is never modified. Cargo metadata runs
locked and offline, so no network access is used. Each mutation must be
detected (non-zero exit) and must name its invariant keyword. Exits zero only
when the clean workspace passes the checker and every mutation is correctly
rejected.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
CHECKER = Path(__file__).resolve().parent / "check_workspace_structure.py"

# A mutation is (display name, expected violation keyword, mutator(root)).
Mutation = tuple[str, str, Callable[[Path], None]]
MUTATIONS: list[Mutation] = []


def _replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise AssertionError(
            f"mutation precondition failed for {path}: expected exactly one occurrence "
            f"of {old!r}, found {count}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def _seed_copy() -> Path:
    """A temporary workspace containing only the structural-gate inputs."""
    tmp = Path(tempfile.mkdtemp(prefix="msgriver-selftest-")) / "ws"
    tmp.mkdir(parents=True)
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
        shutil.copy2(ROOT / name, tmp / name)
    shutil.copytree(ROOT / "crates", tmp / "crates")
    # The two tracked patched sources are structural-gate inputs: the patch
    # table, vendor-manifest, and lock-closure controls mutate or remove them.
    shutil.copytree(ROOT / "third_party", tmp / "third_party")
    return tmp


def run_checker(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stderr + proc.stdout)


def mutation(keyword: str) -> Callable[[Callable[[Path], None]], Callable[[Path], None]]:
    def decorator(fn: Callable[[Path], None]) -> Callable[[Path], None]:
        MUTATIONS.append((fn.__name__, keyword, fn))
        return fn

    return decorator


@mutation("package-version")
def _m_version(root: Path) -> None:
    _replace(root / "Cargo.toml", 'version = "0.1.0-alpha"', 'version = "0.2.0"')


@mutation("resolver")
def _m_resolver(root: Path) -> None:
    _replace(root / "Cargo.toml", 'resolver = "3"', 'resolver = "2"')


@mutation("edition")
def _m_edition(root: Path) -> None:
    _replace(root / "Cargo.toml", 'edition = "2024"', 'edition = "2021"')


@mutation("msrv")
def _m_msrv(root: Path) -> None:
    _replace(root / "Cargo.toml", 'rust-version = "1.89"', 'rust-version = "1.80"')


@mutation("license")
def _m_license(root: Path) -> None:
    _replace(root / "Cargo.toml", 'license = "Apache-2.0"', 'license = "MIT"')


@mutation("publish")
def _m_publish(root: Path) -> None:
    _replace(root / "Cargo.toml", "publish = false", "publish = true")


@mutation("member-seventh")
def _m_seventh(root: Path) -> None:
    extra = root / "crates" / "msgriver-extra"
    (extra / "src").mkdir(parents=True)
    (extra / "src" / "lib.rs").write_text(
        "//! unauthorized seventh package\n#![forbid(unsafe_code)]\n", encoding="utf-8"
    )
    (extra / "Cargo.toml").write_text(
        "[package]\nname = \"msgriver-extra\"\n"
        "version.workspace = true\nedition.workspace = true\n"
        "rust-version.workspace = true\nlicense.workspace = true\npublish.workspace = true\n\n"
        "[lints]\nworkspace = true\n",
        encoding="utf-8",
    )
    _replace(
        root / "Cargo.toml",
        '"crates/msgriver-client",',
        '"crates/msgriver-client",\n    "crates/msgriver-extra",',
    )


@mutation("member-seventh")
def _m_unlisted_seventh(root: Path) -> None:
    extra = root / "crates" / "msgriver-unlisted"
    (extra / "src").mkdir(parents=True)
    (extra / "src" / "lib.rs").write_text(
        "//! unauthorized unlisted package\n#![forbid(unsafe_code)]\n",
        encoding="utf-8",
    )
    (extra / "Cargo.toml").write_text(
        "[package]\nname = \"msgriver-unlisted\"\nversion = \"0.1.0-alpha\"\n"
        "edition = \"2024\"\nrust-version = \"1.89\"\nlicense = \"Apache-2.0\"\n"
        "publish = false\n",
        encoding="utf-8",
    )


@mutation("member-duplicate")
def _m_duplicate_member(root: Path) -> None:
    _replace(
        root / "Cargo.toml",
        '    "crates/msgriver-core",',
        '    "crates/msgriver-core",\n    "crates/msgriver-core",',
    )


@mutation("member")
def _m_missing_member(root: Path) -> None:
    _replace(root / "Cargo.toml", '    "crates/msgriver-store",\n', "")


@mutation("member")
def _m_package_name(root: Path) -> None:
    _replace(
        root / "crates" / "msgriver-store" / "Cargo.toml",
        'name = "msgriver-store"',
        'name = "msgriver-storage"',
    )


@mutation("inheritance")
def _m_package_inheritance(root: Path) -> None:
    _replace(
        root / "crates" / "msgriver-core" / "Cargo.toml",
        "edition.workspace = true",
        'edition = "2024"',
    )


@mutation("inheritance")
def _m_lint_inheritance(root: Path) -> None:
    _replace(
        root / "crates" / "msgriver-core" / "Cargo.toml",
        "[lints]\nworkspace = true",
        "[lints]\nworkspace = false",
    )


@mutation("dependency-direction")
def _m_dep_direction(root: Path) -> None:
    # msgriver-client must be structurally unable to reach the store.
    manifest = root / "crates" / "msgriver-client" / "Cargo.toml"
    _replace(
        manifest,
        "msgriver-protocol.workspace = true",
        "msgriver-protocol.workspace = true\nmsgriver-store.workspace = true",
    )


@mutation("dependency-direction")
def _m_root_core_edge_missing(root: Path) -> None:
    # The composition root must own the direct core edge, not reach it
    # transitively.
    _replace(
        root / "crates" / "msgriver" / "Cargo.toml",
        "msgriver-core.workspace = true\n",
        "",
    )


@mutation("dependency-direction")
def _m_required_dep_missing(root: Path) -> None:
    _replace(
        root / "crates" / "msgriver-client" / "Cargo.toml",
        "msgriver-protocol.workspace = true\n",
        "",
    )


@mutation("dependency-declaration")
def _m_dependency_not_inherited(root: Path) -> None:
    _replace(
        root / "crates" / "msgriver-client" / "Cargo.toml",
        "msgriver-protocol.workspace = true",
        'msgriver-protocol = { path = "../msgriver-protocol" }',
    )


@mutation("dependency-direction")
def _m_dependency_is_dev_only(root: Path) -> None:
    _replace(
        root / "crates" / "msgriver-client" / "Cargo.toml",
        "[dependencies]",
        "[dev-dependencies]",
    )


@mutation("dependency-direction")
def _m_dependency_duplicated_as_dev(root: Path) -> None:
    manifest = root / "crates" / "msgriver-client" / "Cargo.toml"
    _replace(
        manifest,
        "msgriver-protocol.workspace = true",
        "msgriver-protocol.workspace = true\n\n"
        "[dev-dependencies]\nmsgriver-protocol.workspace = true",
    )


@mutation("workspace-dependency")
def _m_workspace_dep_has_extra_policy(root: Path) -> None:
    _replace(
        root / "Cargo.toml",
        'msgriver-protocol = { path = "crates/msgriver-protocol" }',
        'msgriver-protocol = { path = "crates/msgriver-protocol", version = "*" }',
    )


@mutation("third-party-dependency")
def _m_third_party(root: Path) -> None:
    manifest = root / "crates" / "msgriver-core" / "Cargo.toml"
    _replace(
        manifest,
        "[lints]\nworkspace = true",
        '[dependencies]\nserde = "1"\n\n[lints]\nworkspace = true',
    )


@mutation("third-party-dependency")
def _m_target_third_party(root: Path) -> None:
    manifest = root / "crates" / "msgriver-core" / "Cargo.toml"
    _replace(
        manifest,
        "[lints]\nworkspace = true",
        '[target.\'cfg(unix)\'.dependencies]\nserde = "1"\n\n[lints]\nworkspace = true',
    )


@mutation("third-party-dependency")
def _m_dev_third_party(root: Path) -> None:
    # Even an approved name is rejected outside its contracted crate/table.
    manifest = root / "crates" / "msgriver-client" / "Cargo.toml"
    _replace(
        manifest,
        "[lints]\nworkspace = true",
        "[dev-dependencies]\nserde.workspace = true\n\n[lints]\nworkspace = true",
    )


@mutation("dependency-source")
def _m_git_dependency(root: Path) -> None:
    # A-02.2: registry crates only; a git source must fail closed.
    manifest = root / "crates" / "msgriver-protocol" / "Cargo.toml"
    _replace(
        manifest,
        "serde.workspace = true",
        'serde = { git = "https://example.invalid/serde", branch = "main" }',
    )


@mutation("dependency-declaration")
def _m_inline_requirement(root: Path) -> None:
    # Third-party requirements must be inherited from the workspace table,
    # never re-declared inline at the member level.
    manifest = root / "crates" / "msgriver-protocol" / "Cargo.toml"
    _replace(manifest, "serde.workspace = true", 'serde = "1.0.8"')


@mutation("dependency-declaration")
def _m_required_third_party_missing_with_synced_lock(root: Path) -> None:
    # sha2 remains in the closure through the composition root, so only the
    # bidirectional per-crate contract can reject this synchronized removal.
    _replace(
        root / "crates" / "msgriver-store" / "Cargo.toml",
        "sha2.workspace = true\n",
        "",
    )
    _replace(
        root / "Cargo.lock",
        'name = "msgriver-store"\nversion = "0.1.0-alpha"\ndependencies = [\n'
        ' "msgriver-core",\n "rusqlite",\n "sha2",\n]',
        'name = "msgriver-store"\nversion = "0.1.0-alpha"\ndependencies = [\n'
        ' "msgriver-core",\n "rusqlite",\n]',
    )


@mutation("workspace-dependency")
def _m_requirement_widened(root: Path) -> None:
    # Exact pins must not degrade into caret requirements.
    _replace(root / "Cargo.toml", 'sha2 = "=0.10.9"', 'sha2 = "0.10"')


@mutation("workspace-dependency")
def _m_workspace_feature_widened(root: Path) -> None:
    _replace(
        root / "Cargo.toml",
        'features = ["bundled", "backup"]',
        'features = ["bundled", "backup", "hooks"]',
    )


@mutation("dependency-declaration")
def _m_store_dev_feature_widened(root: Path) -> None:
    # The store's test-only rusqlite declaration admits exactly `hooks`.
    manifest = root / "crates" / "msgriver-store" / "Cargo.toml"
    _replace(
        manifest,
        "rusqlite = { workspace = true, features = [\"hooks\"] }",
        "rusqlite = { workspace = true, features = [\"hooks\", \"backup\"] }",
    )


@mutation("dependency-declaration")
def _m_rustix_feature_widened(root: Path) -> None:
    # The composition root's inline platform adapter is pinned exactly.
    manifest = root / "crates" / "msgriver" / "Cargo.toml"
    _replace(
        manifest,
        "features = [\"alloc\", \"fs\", \"process\", \"rand\"]",
        "features = [\"alloc\", \"fs\", \"process\", \"rand\", \"std\"]",
    )


@mutation("unsafe-forbid")
def _m_forbid(root: Path) -> None:
    _replace(
        root / "crates" / "msgriver-core" / "src" / "lib.rs",
        "#![forbid(unsafe_code)]",
        "// (forbid(unsafe_code) removed by mutation)",
    )


@mutation("unsafe-forbid")
def _m_forbid_is_only_a_comment(root: Path) -> None:
    _replace(
        root / "crates" / "msgriver-core" / "src" / "lib.rs",
        "#![forbid(unsafe_code)]",
        "// #![forbid(unsafe_code)]",
    )


@mutation("crate-docs")
def _m_docs(root: Path) -> None:
    source = root / "crates" / "msgriver-protocol" / "src" / "lib.rs"
    text = source.read_text(encoding="utf-8")
    kept = [line for line in text.splitlines() if not line.lstrip().startswith("//!")]
    source.write_text("\n".join(kept).lstrip("\n") + "\n", encoding="utf-8")


@mutation("shipping-feature")
def _m_feature(root: Path) -> None:
    manifest = root / "crates" / "msgriver-store" / "Cargo.toml"
    _replace(
        manifest,
        "[lints]\nworkspace = true",
        "[features]\ntest-utils = []\n\n[lints]\nworkspace = true",
    )


@mutation("release-overflow")
def _m_overflow(root: Path) -> None:
    _replace(root / "Cargo.toml", "overflow-checks = true", "overflow-checks = false")


@mutation("toolchain")
def _m_toolchain(root: Path) -> None:
    _replace(root / "rust-toolchain.toml", 'channel = "1.96.1"', 'channel = "stable"')


@mutation("workspace-root")
def _m_root_toml_corrupt(root: Path) -> None:
    (root / "Cargo.toml").write_text("[workspace\n", encoding="utf-8")


@mutation("patch-table")
def _m_patch_added(root: Path) -> None:
    _replace(
        root / "Cargo.toml",
        'libsqlite3-sys = { path = "third_party/cargo-vendor/libsqlite3-sys" }',
        'libsqlite3-sys = { path = "third_party/cargo-vendor/libsqlite3-sys" }\n'
        'serde = { path = "third_party/cargo-vendor/serde" }',
    )


@mutation("patch-table")
def _m_alternative_patch_registry(root: Path) -> None:
    _replace(
        root / "Cargo.toml",
        "[patch.crates-io]",
        '[patch.private-registry]\nserde = { path = "third_party/cargo-vendor/rusqlite" }\n\n'
        "[patch.crates-io]",
    )


@mutation("patch-table")
def _m_patch_removed(root: Path) -> None:
    _replace(
        root / "Cargo.toml",
        'rusqlite = { path = "third_party/cargo-vendor/rusqlite" }\n',
        "",
    )


@mutation("patch-table")
def _m_patch_repointed(root: Path) -> None:
    _replace(
        root / "Cargo.toml",
        'path = "third_party/cargo-vendor/rusqlite"',
        'path = "third_party/cargo-vendor/libsqlite3-sys"',
    )


@mutation("patch-table")
def _m_vendor_source_absent(root: Path) -> None:
    # The patched sources are guarded, not treated as absent.
    shutil.rmtree(root / "third_party" / "cargo-vendor" / "rusqlite")


@mutation("lockfile")
def _m_lockfile_extra_package(root: Path) -> None:
    lockfile = root / "Cargo.lock"
    lockfile.write_text(
        lockfile.read_text(encoding="utf-8")
        + '\n[[package]]\nname = "serde"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )


@mutation("lockfile")
def _m_lockfile_registry_version_drift(root: Path) -> None:
    _replace(
        root / "Cargo.lock",
        'name = "smallvec"\nversion = "1.16.0"',
        'name = "smallvec"\nversion = "1.17.0"',
    )


@mutation("lockfile")
def _m_lockfile_checksum_removed(root: Path) -> None:
    _replace(
        root / "Cargo.lock",
        'checksum = "b9be42f50aa861c555654aa3a37f52f4b1074bacf4e48fe0ef7fa584e80f1f0f"\n',
        "",
    )


@mutation("lockfile")
def _m_patched_gains_registry_source(root: Path) -> None:
    _replace(
        root / "Cargo.lock",
        'name = "libsqlite3-sys"\nversion = "0.38.1"',
        'name = "libsqlite3-sys"\nversion = "0.38.1"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
    )


@mutation("lockfile")
def _m_lock_local_edge_removed(root: Path) -> None:
    _replace(
        root / "Cargo.lock",
        ' "msgriver-connectors",\n "msgriver-core",\n',
        ' "msgriver-connectors",\n',
    )


@mutation("cargo-metadata")
def _m_extra_shipping_binary(root: Path) -> None:
    binary = root / "crates" / "msgriver-core" / "src" / "bin" / "rogue.rs"
    binary.parent.mkdir(parents=True)
    binary.write_text("fn main() {}\n", encoding="utf-8")


@mutation("cargo-metadata")
def _m_second_composition_binary(root: Path) -> None:
    # The composition root exposes exactly one binary alongside its library.
    binary = root / "crates" / "msgriver" / "src" / "bin" / "rogue.rs"
    binary.parent.mkdir(parents=True)
    binary.write_text("fn main() {}\n", encoding="utf-8")


@mutation("cargo-metadata")
def _m_missing_library_target(root: Path) -> None:
    (root / "crates" / "msgriver-connectors" / "src" / "lib.rs").unlink()


def main() -> int:
    rc, out = run_checker(ROOT)
    if rc != 0:
        print(
            f"POSITIVE FAIL: clean workspace did not pass the checker:\n{out}",
            file=sys.stderr,
        )
        return 1

    failures = 0
    for name, keyword, mutate in MUTATIONS:
        tmp = _seed_copy()
        try:
            mutate(tmp)
            rc, out = run_checker(tmp)
        finally:
            shutil.rmtree(tmp.parent, ignore_errors=True)
        if rc == 0:
            print(
                f"  NOT DETECTED  {name}: checker exited 0 (expected non-zero)",
                file=sys.stderr,
            )
            failures += 1
            continue
        if f"FAIL {keyword}:" not in out:
            print(
                f"  WRONG KEYWORD {name}: expected 'FAIL {keyword}:', got:\n{out}",
                file=sys.stderr,
            )
            failures += 1
            continue
        print(f"  ok  {name} -> {keyword}")

    if failures:
        print(
            f"\nselftest: {failures}/{len(MUTATIONS)} mutation(s) NOT correctly detected.",
            file=sys.stderr,
        )
        return 1
    print(
        f"\nselftest: clean workspace passed and {len(MUTATIONS)} mutation(s) correctly "
        f"detected.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
