#!/usr/bin/env python3
"""Structural checker for the current MsgRiver Rust workspace contract.

Reads Cargo manifests, the lockfile, the pinned toolchain, Cargo metadata, and
crate roots using only the Python standard library. Cargo metadata is executed
offline, locked and with ``--no-deps``, so the check never resolves or downloads
a dependency; that probe reports workspace packages only and is used solely for
package-graph direction and target diagnostics. The third-party source policy
is enforced by the manifest scan and the pinned lockfile closure instead. The
checker fails when the tree drifts from the current A-02.1 / A-02.3 contract:

  * workspace package/version/edition/MSRV/license/publish/resolver/member drift,
    including a seventh workspace package;
  * dependency edges outside the required one-way six-package local graph, in
    the wrong direction, or missing a required edge (the composition root owns
    the client/store/connectors/core edges; no client path reaches the store);
  * a third-party dependency outside the exact per-crate, per-table map of
    requirements, inherited declarations, and feature sets. The eight admitted
    direct crates are serde, serde_json, rusqlite, sha2, hmac, zeroize,
    toml_edit, and the composition root's inline pinned ``rustix`` adapter;
  * a non-registry third-party source (git/path/branch/tag/rev) in any
    dependency declaration;
  * a shared-metadata field or the lint table not inherited from the workspace;
  * a missing crate-level ``//!`` mental-model doc or
    ``#![forbid(unsafe_code)]`` on any shipping crate root, including both the
    composition root's library and binary roots;
  * a shipping Cargo ``[features]`` table (a test/control-plane seam);
  * a release profile without overflow checks;
  * a ``[patch.crates-io]`` table that is not exactly the two tracked
    ``third_party/cargo-vendor`` sources (``rusqlite`` and ``libsqlite3-sys``)
    at their fixed relative paths, or vendored manifests disagreeing with it;
    the patched sources are a tracked supply-chain boundary, never an absence;
  * a lockfile closure that is not exactly the six local workspace packages,
    the two path-patched entries without a registry source/checksum, and the
    forty-four pinned registry entries with checksums (fifty-two entries).

Target policy: each leaf package exposes exactly one shipping library target;
the composition root exposes exactly one library and one binary target.
Integration-test targets are not shipping targets and stay outside the
crate-attribute scope. Build scripts (``custom-build`` targets) are not library
roots either: only the store's migration-DDL embedding build script is
contracted.

Exit status is non-zero if any invariant is violated.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

EXPECTED_VERSION = "0.1.0-alpha"
EXPECTED_EDITION = "2024"
EXPECTED_MSRV = "1.89"
EXPECTED_LICENSE = "MIT"
EXPECTED_RESOLVER = "3"
EXPECTED_TOOLCHAIN = "1.96.1"

# (member path, package name, is_library, allowed local dependency package names)
EXPECTED_MEMBERS: tuple[tuple[str, str, bool, frozenset[str]], ...] = (
    ("crates/msgriver-core", "msgriver-core", True, frozenset()),
    ("crates/msgriver-protocol", "msgriver-protocol", True, frozenset({"msgriver-core"})),
    ("crates/msgriver-store", "msgriver-store", True, frozenset({"msgriver-core"})),
    ("crates/msgriver-connectors", "msgriver-connectors", True, frozenset({"msgriver-core"})),
    ("crates/msgriver-client", "msgriver-client", True, frozenset({"msgriver-protocol"})),
    (
        "crates/msgriver",
        "msgriver",
        False,
        frozenset({"msgriver-client", "msgriver-store", "msgriver-connectors", "msgriver-core"}),
    ),
)
EXPECTED_MEMBER_PATHS = frozenset(m[0] for m in EXPECTED_MEMBERS)
EXPECTED_PACKAGE_NAMES = frozenset(m[1] for m in EXPECTED_MEMBERS)
EXPECTED_MEMBER_BY_NAME = {member[1]: member for member in EXPECTED_MEMBERS}

# The local path dependencies a member is allowed to depend on. ``msgriver``
# is the composition root that nothing depends on, so it has no workspace entry.
EXPECTED_WORKSPACE_DEPS: dict[str, str] = {
    "msgriver-core": "crates/msgriver-core",
    "msgriver-protocol": "crates/msgriver-protocol",
    "msgriver-store": "crates/msgriver-store",
    "msgriver-connectors": "crates/msgriver-connectors",
    "msgriver-client": "crates/msgriver-client",
}

# The exact [workspace.dependencies] third-party declarations (A-02.3 boundary
# currently in force). Every member-level use inherits from here, except the
# composition root's inline rustix adapter declared in its own manifest.
EXPECTED_THIRD_PARTY_WORKSPACE: dict[str, Any] = {
    "serde": "1.0",
    "serde_json": "1.0",
    "rusqlite": {
        "version": "=0.40.1",
        "default-features": False,
        "features": ["bundled", "backup"],
    },
    "sha2": "=0.10.9",
    "hmac": {"version": "=0.12.1", "default-features": False},
    "zeroize": {"version": "=1.9.0", "default-features": False},
    "toml_edit": {"version": "=0.22.27", "default-features": False, "features": ["parse"]},
    "rustls": {"version": "=0.23.45", "default-features": False, "features": ["ring", "std"]},
    "webpki-roots": "=1.0.9",
}
APPROVED_THIRD_PARTY_NAMES = frozenset(EXPECTED_THIRD_PARTY_WORKSPACE) | {"rustix"}

# The exact per-crate, per-table third-party map. Table keys are the plain
# Cargo tables; anything under `target.*` or [build-dependencies] has no entry
# and therefore admits no third-party dependency at all.
EXPECTED_MEMBER_THIRD_PARTY: dict[tuple[str, str], dict[str, Any]] = {
    ("msgriver-protocol", "dependencies"): {
        "serde": {"workspace": True},
        "serde_json": {"workspace": True},
    },
    ("msgriver-store", "dependencies"): {
        "rusqlite": {"workspace": True},
        "sha2": {"workspace": True},
    },
    ("msgriver-store", "dev-dependencies"): {
        "rusqlite": {"workspace": True, "features": ["hooks"]},
    },
    ("msgriver-connectors", "dependencies"): {
        "serde_json": {"workspace": True},
        "rustls": {"workspace": True},
        "webpki-roots": {"workspace": True},
    },
    ("msgriver", "dev-dependencies"): {"rustls": {"workspace": True}},
    ("msgriver", "dependencies"): {
        "hmac": {"workspace": True},
        "rustix": {
            "version": "=1.1.4",
            "default-features": False,
            "features": ["alloc", "fs", "process", "rand"],
        },
        "sha2": {"workspace": True},
        "serde_json": {"workspace": True},
        "toml_edit": {"workspace": True},
        "zeroize": {"workspace": True},
    },
}

# The exact tracked [patch.crates-io] supply-chain boundary.
EXPECTED_PATCHES: dict[str, dict[str, str]] = {
    "rusqlite": {"path": "third_party/cargo-vendor/rusqlite"},
    "libsqlite3-sys": {"path": "third_party/cargo-vendor/libsqlite3-sys"},
}
EXPECTED_PATCHED_VERSIONS: dict[str, str] = {
    "rusqlite": "0.40.1",
    "libsqlite3-sys": "0.38.1",
}

REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

# The complete pinned registry closure of the locked offline graph: together
# with the six local and the two path-patched entries this is exactly the
# fifty-two lockfile packages.
EXPECTED_REGISTRY_LOCK: dict[str, str] = {
    "bitflags": "2.13.1",
    "block-buffer": "0.10.4",
    "cc": "1.4.5",
    "cfg-if": "1.0.4",
    "cpufeatures": "0.2.17",
    "crypto-common": "0.1.7",
    "digest": "0.10.7",
    "equivalent": "1.0.2",
    "errno": "0.3.14",
    "fallible-iterator": "0.3.0",
    "fallible-streaming-iterator": "0.1.9",
    "find-msvc-tools": "0.1.12",
    "generic-array": "0.14.7",
    "hashbrown": "0.17.1",
    "hmac": "0.12.1",
    "indexmap": "2.14.2",
    "itoa": "1.0.18",
    "libc": "0.2.189",
    "linux-raw-sys": "0.12.1",
    "memchr": "2.8.3",
    "pkg-config": "0.3.34",
    "proc-macro2": "1.0.107",
    "quote": "1.0.47",
    "rustix": "1.1.4",
    "serde": "1.0.229",
    "serde_core": "1.0.229",
    "serde_derive": "1.0.229",
    "serde_json": "1.0.151",
    "sha2": "0.10.9",
    "shlex": "2.0.1",
    "smallvec": "1.16.0",
    "subtle": "2.6.1",
    "syn": "3.0.5",
    "toml_datetime": "0.6.11",
    "toml_edit": "0.22.27",
    "typenum": "1.20.1",
    "unicode-ident": "1.0.24",
    "vcpkg": "0.2.15",
    "version_check": "0.9.5",
    "windows-link": "0.2.1",
    "windows-sys": ("0.52.0", "0.61.2"),
    "winnow": "0.7.15",
    "zeroize": "1.9.0",
    "zmij": "1.0.23",
    "getrandom": "0.2.17",
    "once_cell": "1.21.4",
    "ring": "0.17.14",
    "rustls": "0.23.45",
    "rustls-pki-types": "1.15.1",
    "rustls-webpki": "0.103.15",
    "untrusted": "0.9.0",
    "wasi": "0.11.1+wasi-snapshot-preview1",
    "webpki-roots": "1.0.9",
    "windows-targets": "0.52.6",
    "windows_aarch64_gnullvm": "0.52.6",
    "windows_aarch64_msvc": "0.52.6",
    "windows_i686_gnu": "0.52.6",
    "windows_i686_gnullvm": "0.52.6",
    "windows_i686_msvc": "0.52.6",
    "windows_x86_64_gnu": "0.52.6",
    "windows_x86_64_gnullvm": "0.52.6",
    "windows_x86_64_msvc": "0.52.6",
}
EXPECTED_REGISTRY_LOCK_COUNT = 63
EXPECTED_LOCK_TOTAL = (
    len(EXPECTED_MEMBERS) + len(EXPECTED_PATCHES) + EXPECTED_REGISTRY_LOCK_COUNT
)

# Keys that would give a third-party dependency a non-registry source. The
# A-02.2 policy is registry crates only; the two vendored patches above are the
# sole sanctioned path exception and live in the patch table, never in a
# dependency declaration.
SOURCE_POLICY_KEYS = ("git", "path", "branch", "tag", "rev", "registry", "registry-index")

INHERITED_FIELDS = ("version", "edition", "rust-version", "license", "publish")
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
SHIPPING_KINDS = {"lib", "bin", "cdylib", "dylib", "staticlib", "proc-macro"}


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _is_inherited(value: Any) -> bool:
    return isinstance(value, dict) and value.get("workspace") is True


def _iter_deps(manifest: dict[str, Any]) -> list[tuple[str, str, Any]]:
    """Return every dependency declaration without hiding duplicate-table entries."""
    found: list[tuple[str, str, Any]] = []
    for key in DEPENDENCY_TABLES:
        table = manifest.get(key)
        if isinstance(table, dict):
            for name, entry in table.items():
                found.append((name, key, entry))
    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for selector, target_data in targets.items():
            if not isinstance(target_data, dict):
                continue
            for key in DEPENDENCY_TABLES:
                table = target_data.get(key)
                if isinstance(table, dict):
                    for name, entry in table.items():
                        found.append((name, f"target.{selector}.{key}", entry))
    return found


def _entry_signature(entry: Any) -> Any:
    """Canonical comparable form; feature lists compare order-insensitively."""
    if isinstance(entry, dict):
        rest = tuple(
            sorted((key, repr(value)) for key, value in entry.items() if key != "features")
        )
        features = entry.get("features")
        normalized = tuple(sorted(features)) if isinstance(features, list) else repr(features)
        return ("table", rest, normalized)
    return ("shorthand", repr(entry))


def _has_non_registry_source(entry: Any) -> bool:
    return isinstance(entry, dict) and any(key in SOURCE_POLICY_KEYS for key in entry)


def _has_crate_doc(text: str) -> bool:
    for line in text.splitlines():
        if line.strip():
            return line.strip().startswith("//!")
    return False


def _has_unsafe_forbid(text: str) -> bool:
    """Require the exact active crate attribute, not a comment/string substring."""
    return any(line.strip() == "#![forbid(unsafe_code)]" for line in text.splitlines())


class WorkspaceCheck:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.violations: list[tuple[str, str]] = []

    def fail(self, keyword: str, message: str) -> None:
        self.violations.append((keyword, message))

    def _expect_value(
        self, keyword: str, actual: Any, expected: Any, label: str
    ) -> None:
        if actual != expected:
            self.fail(keyword, f"{label} must be {expected!r}, got {actual!r}")

    def check(self) -> list[tuple[str, str]]:
        root_cargo = self.root / "Cargo.toml"
        if not root_cargo.is_file():
            self.fail("workspace-root", f"missing workspace manifest {root_cargo}")
            return self.violations

        self._check_toolchain()
        self._check_lockfile()
        self._check_package_inventory()

        try:
            data = _load_toml(root_cargo)
        except tomllib.TOMLDecodeError as error:
            self.fail("workspace-root", f"root Cargo.toml is unreadable: {error}")
            return self.violations
        workspace = data.get("workspace", {})
        if not isinstance(workspace, dict):
            self.fail("workspace-root", "root Cargo.toml has no [workspace] table")
            return self.violations

        if str(workspace.get("resolver")) != EXPECTED_RESOLVER:
            self.fail(
                "resolver",
                f"workspace.resolver must be {EXPECTED_RESOLVER!r}, "
                f"got {workspace.get('resolver')!r}",
            )

        pkg = workspace.get("package", {})
        if not isinstance(pkg, dict):
            pkg = {}
        self._expect_value(
            "package-version", pkg.get("version"), EXPECTED_VERSION, "workspace.package.version"
        )
        self._expect_value(
            "edition", pkg.get("edition"), EXPECTED_EDITION, "workspace.package.edition"
        )
        self._expect_value(
            "msrv", pkg.get("rust-version"), EXPECTED_MSRV, "workspace.package.rust-version"
        )
        self._expect_value(
            "license", pkg.get("license"), EXPECTED_LICENSE, "workspace.package.license"
        )
        if pkg.get("publish") is not False:
            self.fail(
                "publish",
                f"workspace.package.publish must be false while unreleased, "
                f"got {pkg.get('publish')!r}",
            )

        members = workspace.get("members", [])
        actual_members = list(members) if isinstance(members, list) else []
        actual_member_set = set(actual_members)
        if len(actual_members) != len(actual_member_set):
            duplicates = sorted(
                path for path in actual_member_set if actual_members.count(path) > 1
            )
            self.fail(
                "member-duplicate",
                f"workspace member paths must be unique; duplicates: {duplicates}",
            )
        if len(actual_member_set) > len(EXPECTED_MEMBERS):
            self.fail(
                "member-seventh",
                f"workspace declares {len(actual_member_set)} members; exactly "
                f"{len(EXPECTED_MEMBERS)} A-02.1 packages are permitted (extras: "
                f"{sorted(actual_member_set - EXPECTED_MEMBER_PATHS)})",
            )
        for path in sorted(actual_member_set):
            if path not in EXPECTED_MEMBER_PATHS:
                self.fail(
                    "member",
                    f"workspace member {path!r} is not one of the six permitted "
                    f"A-02.1 packages",
                )
        for path in sorted(EXPECTED_MEMBER_PATHS - actual_member_set):
            self.fail("member", f"required A-02.1 workspace member {path!r} is missing")

        release = data.get("profile", {}).get("release", {})
        if not isinstance(release, dict):
            release = {}
        if release.get("overflow-checks") is not True:
            self.fail(
                "release-overflow",
                f"[profile.release] must set overflow-checks = true, "
                f"got {release.get('overflow-checks')!r}",
            )

        self._check_workspace_dependencies(workspace.get("dependencies", {}))
        self._check_patch_table(data)

        for rel_path, name, is_lib, allowed_deps in EXPECTED_MEMBERS:
            self._check_member(rel_path, name, is_lib, allowed_deps)

        # This is deliberately last: manifest checks retain their precise
        # invariant keywords even when a mutation also makes Cargo metadata
        # reject the locked graph.
        self._check_cargo_metadata()

        return self.violations

    def _check_toolchain(self) -> None:
        path = self.root / "rust-toolchain.toml"
        if not path.is_file():
            self.fail("toolchain", f"missing pinned toolchain file {path}")
            return
        try:
            data = _load_toml(path)
        except tomllib.TOMLDecodeError as error:
            self.fail("toolchain", f"pinned toolchain file is unreadable: {error}")
            return
        toolchain = data.get("toolchain", {})
        if not isinstance(toolchain, dict):
            toolchain = {}
        if toolchain.get("channel") != EXPECTED_TOOLCHAIN:
            self.fail(
                "toolchain",
                f"toolchain.channel must be {EXPECTED_TOOLCHAIN!r}, "
                f"got {toolchain.get('channel')!r}",
            )
        components = toolchain.get("components")
        if (
            not isinstance(components, list)
            or len(components) != 2
            or set(components) != {"clippy", "rustfmt"}
        ):
            self.fail(
                "toolchain",
                "toolchain.components must contain exactly clippy and rustfmt",
            )

    def _check_lockfile(self) -> None:
        path = self.root / "Cargo.lock"
        if not path.is_file():
            self.fail("lockfile", f"missing committed lockfile {path}")
            return
        try:
            data = _load_toml(path)
        except tomllib.TOMLDecodeError as error:
            self.fail("lockfile", f"committed lockfile is unreadable: {error}")
            return
        if data.get("version") != 4:
            self.fail(
                "lockfile",
                f"Cargo.lock format must be 4, got {data.get('version')!r}",
            )
        packages = data.get("package", [])
        if not isinstance(packages, list):
            packages = []
        entries = [entry for entry in packages if isinstance(entry, dict)]

        counts = {"local": 0, "patched": 0, "registry": 0}
        for entry in entries:
            name = entry.get("name")
            version = entry.get("version")
            if name in EXPECTED_PACKAGE_NAMES:
                counts["local"] += 1
                if version != EXPECTED_VERSION:
                    self.fail(
                        "lockfile",
                        f"Cargo.lock package {name!r} must be {EXPECTED_VERSION!r}",
                    )
                if "source" in entry or "checksum" in entry:
                    self.fail(
                        "lockfile",
                        f"Cargo.lock package {name!r} must be a local entry without "
                        "a registry source or checksum",
                    )
                allowed = EXPECTED_MEMBER_BY_NAME[name][3]
                dependencies = entry.get("dependencies", [])
                actual_local = {
                    str(dep).split(" ")[0]
                    for dep in (dependencies if isinstance(dependencies, list) else [])
                    if str(dep).split(" ")[0] in EXPECTED_PACKAGE_NAMES
                }
                if actual_local != set(allowed):
                    self.fail(
                        "lockfile",
                        f"Cargo.lock package {name!r} local dependencies must be "
                        f"{sorted(allowed)}, got {sorted(actual_local)}",
                    )
            elif name in EXPECTED_PATCHED_VERSIONS:
                counts["patched"] += 1
                if version != EXPECTED_PATCHED_VERSIONS[name]:
                    self.fail(
                        "lockfile",
                        f"Cargo.lock patched package {name!r} must be "
                        f"{EXPECTED_PATCHED_VERSIONS[name]!r}, got {version!r}",
                    )
                if "source" in entry or "checksum" in entry:
                    self.fail(
                        "lockfile",
                        f"Cargo.lock patched package {name!r} must carry no registry "
                        "source or checksum; it resolves through the tracked "
                        "[patch.crates-io] path",
                    )
            else:
                expected_version = EXPECTED_REGISTRY_LOCK.get(name)
                counts["registry"] += 1
                if expected_version is None:
                    self.fail(
                        "lockfile",
                        f"Cargo.lock contains {name!r} outside the pinned 6-local + "
                        "2-patched + 44-registry closure",
                    )
                elif version not in (
                    expected_version
                    if isinstance(expected_version, tuple)
                    else (expected_version,)
                ):
                    self.fail(
                        "lockfile",
                        f"Cargo.lock registry package {name!r} must be pinned to "
                        f"{expected_version!r}, got {version!r}",
                    )
                if entry.get("source") != REGISTRY_SOURCE:
                    self.fail(
                        "lockfile",
                        f"Cargo.lock package {name!r} must use the registry source "
                        f"{REGISTRY_SOURCE!r}; git or path third-party sources are "
                        f"forbidden, got {entry.get('source')!r}",
                    )
                checksum = entry.get("checksum")
                if not isinstance(checksum, str) or not checksum:
                    self.fail(
                        "lockfile",
                        f"Cargo.lock registry package {name!r} must carry its "
                        "supply-chain checksum",
                    )

        if len(entries) != EXPECTED_LOCK_TOTAL:
            self.fail(
                "lockfile",
                f"Cargo.lock must contain exactly {EXPECTED_LOCK_TOTAL} packages "
                f"(6 local, 2 patched, {len(EXPECTED_REGISTRY_LOCK)} registry); "
                f"got {len(entries)}",
            )
        if counts["local"] != len(EXPECTED_MEMBERS):
            self.fail(
                "lockfile",
                f"Cargo.lock must contain exactly the six local workspace packages; "
                f"got {counts['local']}",
            )
        if counts["patched"] != len(EXPECTED_PATCHES):
            self.fail(
                "lockfile",
                f"Cargo.lock must contain exactly the two path-patched entries "
                f"{sorted(EXPECTED_PATCHES)}; got {counts['patched']}",
            )
        if counts["registry"] != EXPECTED_REGISTRY_LOCK_COUNT:
            self.fail(
                "lockfile",
                f"Cargo.lock must contain exactly {len(EXPECTED_REGISTRY_LOCK)} "
                f"registry packages; got {counts['registry']}",
            )

    def _check_package_inventory(self) -> None:
        crates = self.root / "crates"
        manifests = {
            path.parent.relative_to(self.root).as_posix()
            for path in crates.glob("*/Cargo.toml")
            if path.is_file()
        }
        extras = manifests - EXPECTED_MEMBER_PATHS
        if extras:
            self.fail(
                "member-seventh",
                f"crate directories contain unauthorized package manifests: {sorted(extras)}",
            )
        missing = EXPECTED_MEMBER_PATHS - manifests
        for path in sorted(missing):
            self.fail("member", f"required package manifest {path!r}/Cargo.toml is missing")

    def _check_cargo_metadata(self) -> None:
        command = [
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--locked",
            "--offline",
            "--manifest-path",
            str(self.root / "Cargo.toml"),
        ]
        try:
            process = subprocess.run(
                command,
                cwd=self.root,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            self.fail("cargo-metadata", f"offline locked Cargo metadata failed: {error}")
            return
        if process.returncode != 0:
            detail = (process.stderr or process.stdout).strip().splitlines()
            last_line = detail[-1][:400] if detail else "no diagnostic"
            self.fail(
                "cargo-metadata",
                f"offline locked Cargo metadata exited {process.returncode}: {last_line}",
            )
            return
        try:
            metadata = json.loads(process.stdout)
        except json.JSONDecodeError as error:
            self.fail("cargo-metadata", f"Cargo metadata returned invalid JSON: {error}")
            return

        # The --no-deps probe is bounded to workspace packages; it validates the
        # local graph direction and target shape only. Third-party source and
        # closure policy live in the manifest scan and lockfile checks above.
        packages = metadata.get("packages", [])
        if not isinstance(packages, list):
            packages = []
        names = [package.get("name") for package in packages if isinstance(package, dict)]
        if len(packages) != len(EXPECTED_MEMBERS) or set(names) != EXPECTED_PACKAGE_NAMES:
            self.fail(
                "cargo-metadata",
                "Cargo metadata must report exactly the six A-02.1 packages; "
                f"got {sorted(str(name) for name in names)}",
            )
            return

        package_ids = {
            package.get("id")
            for package in packages
            if isinstance(package, dict) and isinstance(package.get("id"), str)
        }
        workspace_ids = set(metadata.get("workspace_members", []))
        default_ids = set(metadata.get("workspace_default_members", []))
        if workspace_ids != package_ids or default_ids != package_ids:
            self.fail(
                "cargo-metadata",
                "Cargo workspace/default member IDs must equal the exact six-package set",
            )

        for package in packages:
            if not isinstance(package, dict):
                self.fail("cargo-metadata", "Cargo metadata contains a non-object package")
                continue
            name = package.get("name")
            member = EXPECTED_MEMBER_BY_NAME.get(name)
            if member is None:
                continue
            rel_path, _, is_lib, allowed_deps = member
            expected_manifest = (self.root / rel_path / "Cargo.toml").resolve()
            try:
                actual_manifest = Path(str(package.get("manifest_path"))).resolve()
            except OSError as error:
                self.fail("cargo-metadata", f"cannot resolve manifest for {name!r}: {error}")
                continue
            expected_values = {
                "version": EXPECTED_VERSION,
                "edition": EXPECTED_EDITION,
                "rust_version": EXPECTED_MSRV,
                "license": EXPECTED_LICENSE,
            }
            for field, expected in expected_values.items():
                if package.get(field) != expected:
                    self.fail(
                        "cargo-metadata",
                        f"Cargo metadata {name}.{field} must be {expected!r}, "
                        f"got {package.get(field)!r}",
                    )
            if package.get("source") is not None or package.get("publish") != []:
                self.fail(
                    "cargo-metadata",
                    f"Cargo metadata package {name!r} must be local and unpublished",
                )
            if actual_manifest != expected_manifest:
                self.fail(
                    "cargo-metadata",
                    f"Cargo metadata package {name!r} resolved from {actual_manifest}, "
                    f"expected {expected_manifest}",
                )

            targets = package.get("targets", [])
            if not isinstance(targets, list):
                targets = []
            shipping_targets = [
                target
                for target in targets
                if isinstance(target, dict)
                and set(target.get("kind", [])) & SHIPPING_KINDS
            ]
            expected_shipping_sources = (
                {"lib": (self.root / rel_path / "src" / "lib.rs").resolve()}
                if is_lib
                else {
                    "lib": (self.root / rel_path / "src" / "lib.rs").resolve(),
                    "bin": (self.root / rel_path / "src" / "main.rs").resolve(),
                }
            )
            expected_kinds = sorted(expected_shipping_sources)
            if len(shipping_targets) != len(expected_shipping_sources):
                self.fail(
                    "cargo-metadata",
                    f"Cargo metadata package {name!r} must expose exactly the shipping "
                    f"targets {expected_kinds}, got {len(shipping_targets)}",
                )
            else:
                for target in shipping_targets:
                    kinds = target.get("kind", [])
                    try:
                        source = Path(str(target.get("src_path"))).resolve()
                    except OSError as error:
                        self.fail(
                            "cargo-metadata",
                            f"cannot resolve target source for {name!r}: {error}",
                        )
                        continue
                    if len(kinds) != 1 or kinds[0] not in expected_shipping_sources:
                        self.fail(
                            "cargo-metadata",
                            f"Cargo metadata package {name!r} shipping target kinds "
                            f"must be {expected_kinds}, got {kinds!r}",
                        )
                        continue
                    if source != expected_shipping_sources[kinds[0]]:
                        self.fail(
                            "cargo-metadata",
                            f"Cargo metadata shipping target for {name!r} drifted from "
                            f"{expected_shipping_sources[kinds[0]]}",
                        )

            # Explicit build-script policy: a `custom-build` target is not a
            # library root and never enters the crate-attribute scope. The
            # store's migration-DDL embedding build script is the only contracted one.
            for target in targets:
                if not isinstance(target, dict):
                    continue
                if "custom-build" in set(target.get("kind", [])) and name != "msgriver-store":
                    self.fail(
                        "cargo-metadata",
                        f"Cargo metadata package {name!r} declares a build script; "
                        "only the store's migration-DDL embedding build script is contracted",
                    )

            dependencies = package.get("dependencies", [])
            if not isinstance(dependencies, list):
                dependencies = []
            local_dependencies = [
                dependency
                for dependency in dependencies
                if isinstance(dependency, dict)
                and dependency.get("name") in EXPECTED_PACKAGE_NAMES
            ]
            dep_names = [
                dependency.get("name") for dependency in local_dependencies
            ]
            if len(dep_names) != len(set(dep_names)) or set(dep_names) != set(allowed_deps):
                self.fail(
                    "cargo-metadata",
                    f"Cargo metadata local dependencies for {name!r} must be "
                    f"{sorted(allowed_deps)}, got {sorted(str(dep) for dep in dep_names)}",
                )
                continue
            for dependency in local_dependencies:
                dep_name = dependency.get("name")
                dep_member = EXPECTED_MEMBER_BY_NAME.get(dep_name)
                if dep_member is None:
                    continue
                expected_path = (self.root / dep_member[0]).resolve()
                actual_path = Path(str(dependency.get("path"))).resolve()
                exact_local = (
                    dependency.get("source") is None
                    and actual_path == expected_path
                    and dependency.get("kind") is None
                    and dependency.get("rename") is None
                    and dependency.get("optional") is False
                    and dependency.get("target") is None
                    and dependency.get("registry") is None
                    and dependency.get("features") == []
                    and dependency.get("req") == "*"
                )
                if not exact_local:
                    self.fail(
                        "cargo-metadata",
                        f"Cargo metadata dependency {name!r} -> {dep_name!r} is not the "
                        "exact locked local normal edge",
                    )

    def _check_workspace_dependencies(self, deps: Any) -> None:
        if not isinstance(deps, dict):
            deps = {}
        for name, entry in deps.items():
            expected_path = EXPECTED_WORKSPACE_DEPS.get(name)
            if expected_path is not None:
                if entry != {"path": expected_path}:
                    self.fail(
                        "workspace-dependency",
                        f"workspace.dependencies.{name} must be "
                        f"{{ path = {expected_path!r} }}, got {entry!r}",
                    )
            elif name in EXPECTED_PACKAGE_NAMES:
                self.fail(
                    "workspace-dependency",
                    f"workspace.dependencies.{name!r} is a workspace package that "
                    f"nothing should depend on",
                )
            elif name in EXPECTED_THIRD_PARTY_WORKSPACE:
                expected = EXPECTED_THIRD_PARTY_WORKSPACE[name]
                if _entry_signature(entry) != _entry_signature(expected):
                    if _has_non_registry_source(entry):
                        self.fail(
                            "dependency-source",
                            f"workspace.dependencies.{name!r} must come from the "
                            "registry with the pinned declaration "
                            f"{expected!r}; git/path sources are forbidden, "
                            f"got {entry!r}",
                        )
                    else:
                        self.fail(
                            "workspace-dependency",
                            f"workspace.dependencies.{name} must be exactly "
                            f"{expected!r}, got {entry!r}",
                        )
            else:
                self.fail(
                    "third-party-dependency",
                    f"workspace.dependencies declares unauthorized dependency "
                    f"{name!r}; the eight-crate A-02.3 direct budget admits no "
                    "implicit exception",
                )
        for name, expected_path in EXPECTED_WORKSPACE_DEPS.items():
            if name not in deps:
                self.fail(
                    "workspace-dependency",
                    f"workspace.dependencies missing local dependency {name!r} -> "
                    f"{{ path = {expected_path!r} }}",
                )
        for name in EXPECTED_THIRD_PARTY_WORKSPACE:
            if name not in deps:
                self.fail(
                    "workspace-dependency",
                    f"workspace.dependencies missing pinned third-party dependency "
                    f"{name!r} = {EXPECTED_THIRD_PARTY_WORKSPACE[name]!r}",
                )

    def _check_patch_table(self, data: dict[str, Any]) -> None:
        patch = data.get("patch")
        if isinstance(patch, dict):
            for registry in patch:
                if registry != "crates-io":
                    self.fail(
                        "patch-table",
                        f"[patch.{registry}] is forbidden; only the exact "
                        "[patch.crates-io] vendor boundary is permitted",
                    )
        table = patch.get("crates-io") if isinstance(patch, dict) else None
        if not isinstance(table, dict):
            table = {}
        for name, entry in table.items():
            expected = EXPECTED_PATCHES.get(name)
            if expected is None:
                self.fail(
                    "patch-table",
                    f"[patch.crates-io] declares unauthorized patch {name!r}; only "
                    f"{sorted(EXPECTED_PATCHES)} are the tracked supply-chain boundary",
                )
                continue
            if entry != expected:
                self.fail(
                    "patch-table",
                    f"[patch.crates-io] {name!r} must be {expected!r}, got {entry!r}",
                )
        for name, expected in EXPECTED_PATCHES.items():
            if name not in table:
                self.fail(
                    "patch-table",
                    f"[patch.crates-io] missing required patch {name!r} -> {expected!r}",
                )
                continue
            vendor_manifest = self.root / expected["path"] / "Cargo.toml"
            if not vendor_manifest.is_file():
                self.fail(
                    "patch-table",
                    f"tracked vendor source {vendor_manifest} is missing; the "
                    "canonical tree must keep its two patched sources present",
                )
                continue
            try:
                vdata = _load_toml(vendor_manifest)
            except tomllib.TOMLDecodeError as error:
                self.fail(
                    "patch-table",
                    f"tracked vendor manifest {vendor_manifest} is unreadable: {error}",
                )
                continue
            vpackage = vdata.get("package", {})
            if not isinstance(vpackage, dict):
                vpackage = {}
            expected_version = EXPECTED_PATCHED_VERSIONS[name]
            if vpackage.get("name") != name or vpackage.get("version") != expected_version:
                self.fail(
                    "patch-table",
                    f"vendor source {expected['path']} must be package {name!r} "
                    f"{expected_version!r}, got {vpackage.get('name')!r} "
                    f"{vpackage.get('version')!r}",
                )

    def _check_member(
        self, rel_path: str, name: str, is_lib: bool, allowed_deps: frozenset[str]
    ) -> None:
        member_cargo = self.root / rel_path / "Cargo.toml"
        if not member_cargo.is_file():
            self.fail("member", f"missing member manifest {member_cargo}")
            return
        try:
            mdata = _load_toml(member_cargo)
        except tomllib.TOMLDecodeError as error:
            self.fail("member", f"member manifest {member_cargo} is unreadable: {error}")
            return
        mpackage = mdata.get("package", {})
        if not isinstance(mpackage, dict):
            mpackage = {}
        if mpackage.get("name") != name:
            self.fail(
                "member", f"{rel_path} package name must be {name!r}, got {mpackage.get('name')!r}"
            )

        for field in INHERITED_FIELDS:
            if not _is_inherited(mpackage.get(field)):
                self.fail(
                    "inheritance",
                    f"{rel_path} [package].{field} must be inherited via "
                    f"`{field}.workspace = true`, got {mpackage.get(field)!r}",
                )

        lints = mdata.get("lints")
        if not (isinstance(lints, dict) and lints.get("workspace") is True):
            self.fail(
                "inheritance",
                f"{rel_path} must inherit lints via `[lints]` with `workspace = true`",
            )

        features = mdata.get("features")
        if features is not None:
            keys = sorted(features.keys()) if isinstance(features, dict) else features
            self.fail(
                "shipping-feature",
                f"{rel_path} must not declare a Cargo [features] table; no shipping "
                f"test/control-plane feature is permitted. Found: {keys}",
            )

        declared = _iter_deps(mdata)
        normal_local: set[str] = set()
        occurrences: dict[str, int] = {}
        for dep_name, dep_kind, entry in declared:
            occurrences[dep_name] = occurrences.get(dep_name, 0) + 1
            if dep_name in EXPECTED_PACKAGE_NAMES:
                if dep_name not in allowed_deps:
                    self.fail(
                        "dependency-direction",
                        f"{rel_path} declares local dependency {dep_name!r} ({dep_kind}) "
                        f"which is not permitted in its A-02.1 direction; allowed local "
                        f"deps: {sorted(allowed_deps) or '<none>'}",
                    )
                    continue
                if dep_kind != "dependencies":
                    self.fail(
                        "dependency-direction",
                        f"{rel_path} must declare required local dependency {dep_name!r} "
                        f"once under [dependencies], not {dep_kind}",
                    )
                    continue
                normal_local.add(dep_name)
                if entry != {"workspace": True}:
                    self.fail(
                        "dependency-declaration",
                        f"{rel_path} dependency {dep_name!r} must be inherited exactly "
                        "with `.workspace = true`; direct path/version/source options are "
                        "forbidden",
                    )
            else:
                expected_entry = EXPECTED_MEMBER_THIRD_PARTY.get((name, dep_kind), {}).get(
                    dep_name
                )
                if dep_name not in APPROVED_THIRD_PARTY_NAMES or expected_entry is None:
                    self.fail(
                        "third-party-dependency",
                        f"{rel_path} declares third-party dependency {dep_name!r} "
                        f"({dep_kind}) outside the exact per-crate A-02.3 dependency "
                        "map; a new crate requires a contract amendment, not an "
                        "implicit checker exception",
                    )
                    continue
                if _entry_signature(entry) != _entry_signature(expected_entry):
                    if _has_non_registry_source(entry):
                        self.fail(
                            "dependency-source",
                            f"{rel_path} dependency {dep_name!r} ({dep_kind}) must be "
                            f"the registry declaration {expected_entry!r}; git/path "
                            f"sources are forbidden, got {entry!r}",
                        )
                    else:
                        self.fail(
                            "dependency-declaration",
                            f"{rel_path} dependency {dep_name!r} ({dep_kind}) must be "
                            f"exactly {expected_entry!r}, got {entry!r}",
                        )
        for required in sorted(allowed_deps):
            if required not in normal_local:
                self.fail(
                    "dependency-direction",
                    f"{rel_path} is missing required normal local dependency "
                    f"{required!r} (A-02.1)",
                )
            if occurrences.get(required, 0) > 1:
                self.fail(
                    "dependency-direction",
                    f"{rel_path} declares local dependency {required!r} more than once",
                )

        # The direct third-party contract is exact in both directions. A
        # dependency that happens to remain in the global lock closure through
        # another crate must not make a required per-crate edge optional.
        for (expected_package, expected_table), expected_deps in (
            EXPECTED_MEMBER_THIRD_PARTY.items()
        ):
            if expected_package != name:
                continue
            for expected_name in expected_deps:
                if not any(
                    dep_name == expected_name and dep_kind == expected_table
                    for dep_name, dep_kind, _entry in declared
                ):
                    self.fail(
                        "dependency-declaration",
                        f"{rel_path} is missing required third-party dependency "
                        f"{expected_name!r} under [{expected_table}]",
                    )

        # Every shipping crate root carries the A-02.1 attributes: the
        # composition root owns both the library and the binary root.
        crate_roots = [self.root / rel_path / "src" / "lib.rs"]
        if not is_lib:
            crate_roots.append(self.root / rel_path / "src" / "main.rs")
        for crate_root in crate_roots:
            if not crate_root.is_file():
                self.fail("crate-root", f"{rel_path} missing crate root {crate_root}")
                continue
            text = crate_root.read_text(encoding="utf-8")
            if not _has_unsafe_forbid(text):
                self.fail(
                    "unsafe-forbid",
                    f"{rel_path} crate root {crate_root.name} must contain "
                    "`#![forbid(unsafe_code)]`",
                )
            if not _has_crate_doc(text):
                self.fail(
                    "crate-docs",
                    f"{rel_path} crate root {crate_root.name} must begin with a `//!` "
                    "crate-level mental-model doc comment",
                )


def main(argv: list[str] | None = None) -> int:
    default_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=default_root, help="workspace root to check"
    )
    args = parser.parse_args(argv)

    violations = WorkspaceCheck(args.root).check()
    if not violations:
        print("workspace-structure: OK", file=sys.stderr)
        return 0
    print(f"workspace-structure: {len(violations)} violation(s)", file=sys.stderr)
    for keyword, message in violations:
        print(f"  FAIL {keyword}: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
