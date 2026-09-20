#!/usr/bin/env python3
"""Frozen Task 0316 RED/acceptance test for the public projection builder.

With no builder, this validates the tracked public manifest then returns one
stable RED result.  Once the builder exists, the same test covers clean
materialization/verification and all required rejection cases in disposable
local Git clones.  It never writes to the canonical worktree or uses a network.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_REL = "release/publication/public-source-files.txt"
BUILDER_REL = "scripts/build_public_projection.py"
SELFTEST_REL = "scripts/check_public_projection_selftest.py"
EXPECTED_TOTAL = 488
EXCLUDED_TOP = frozenset({"reviews", "tasks", "logs", "scripts", "security"})
EXCLUDED_ROOT = frozenset({"AGENTS.md", "CLAUDE.md", "session.md"})
RETAINED_TASKS = frozenset({"tasks/0010-v2-ddl-contract.md"})
RETAINED_SCRIPTS = frozenset(
    {
        "scripts/check_specs.py",
        "scripts/spec_structure.py",
        "scripts/check_task0313_public_identifier_migration.py",
        "scripts/check_workspace_structure.py",
        "scripts/check_workspace_structure_selftest.py",
        "scripts/generate_red_protocol_catalog.py",
        SELFTEST_REL,
    }
)
RED_MESSAGE = (
    f"RED: {BUILDER_REL} is absent; "
    "public projection builder implementation is still missing"
)


def fail(errors: list[str], message: str) -> None:
    errors.append(message)
    print(f"FAIL: {message}")


def command(arguments: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, cwd=cwd, text=True, capture_output=True, check=False)


def tracked_paths(root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        text=False,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace").strip())
    return {item.decode("utf-8") for item in result.stdout.split(b"\0") if item}


def expected_surface(root: Path) -> set[str]:
    expected: set[str] = set()
    for entry in tracked_paths(root):
        top = entry.split("/", 1)[0]
        if ("/" not in entry and entry in EXCLUDED_ROOT) or top in EXCLUDED_TOP:
            continue
        try:
            mode = os.lstat(root / entry).st_mode
        except OSError:
            continue
        if stat.S_ISREG(mode) and not stat.S_ISLNK(mode):
            expected.add(entry)
    expected |= RETAINED_TASKS | RETAINED_SCRIPTS | {MANIFEST_REL, BUILDER_REL}
    return expected


def validate_manifest(root: Path, errors: list[str]) -> list[str]:
    path = root / MANIFEST_REL
    try:
        mode = os.lstat(path).st_mode
        data = path.read_bytes()
    except OSError as error:
        fail(errors, f"manifest is unreadable: {error}")
        return []
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        fail(errors, "manifest must be a regular non-symlink file")
        return []
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(errors, f"manifest must be UTF-8: {error}")
        return []
    if b"\r" in data:
        fail(errors, "manifest must be LF-only")
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        fail(errors, "manifest must have exactly one terminal newline")
    raw = data.split(b"\n")
    lines = raw[:-1] if raw and raw[-1] == b"" else raw
    for number, line in enumerate(lines, 1):
        if not line:
            fail(errors, f"manifest line {number} is empty")
            continue
        entry = line.decode("utf-8", "replace")
        if entry.startswith("/") or any(part in ("", ".", "..") for part in entry.split("/")):
            fail(errors, f"manifest line {number} is not a normalized relative POSIX path")
    if lines != sorted(lines):
        fail(errors, "manifest is not strict bytewise lexical order or has duplicates")
    entries = [line.decode("utf-8") for line in lines if line]
    entry_set = set(entries)
    if len(entry_set) != EXPECTED_TOTAL:
        fail(errors, f"manifest must contain {EXPECTED_TOTAL} paths; got {len(entry_set)}")
    try:
        expected = expected_surface(root)
    except RuntimeError as error:
        fail(errors, f"cannot read tracked public surface: {error}")
        return entries
    if entry_set != expected:
        fail(errors, f"manifest differs from tracked public surface; missing={sorted(expected-entry_set)[:8]!r}, extra={sorted(entry_set-expected)[:8]!r}")
    required = RETAINED_TASKS | RETAINED_SCRIPTS | {MANIFEST_REL, BUILDER_REL}
    for entry in sorted(required - entry_set):
        fail(errors, f"manifest omits required public input {entry!r}")
    for entry in sorted(entry_set):
        if entry.startswith(("reviews/", "logs/", "security/gitleaks-manifest")):
            fail(errors, f"manifest includes internal evidence {entry!r}")
        if entry.startswith("tasks/") and entry not in RETAINED_TASKS:
            fail(errors, f"manifest includes internal task {entry!r}")
        if entry.startswith("scripts/") and entry not in RETAINED_SCRIPTS | {BUILDER_REL}:
            fail(errors, f"manifest includes internal automation {entry!r}")
    return entries


def builder(source: Path, output: Path, verify: bool = False) -> subprocess.CompletedProcess[str]:
    args = [sys.executable, BUILDER_REL]
    if verify:
        args.append("--verify")
    args.extend(["--source", str(source), "--output", str(output)])
    return command(args, source)


def must_materialize(source: Path, output: Path) -> None:
    result = builder(source, output)
    if result.returncode:
        raise AssertionError(f"clean materialization failed: {result.stdout}{result.stderr}")
    result = builder(source, output, verify=True)
    if result.returncode:
        raise AssertionError(f"clean verification failed: {result.stdout}{result.stderr}")


def must_reject(source: Path, output: Path, label: str, verify: bool = False) -> None:
    result = builder(source, output, verify)
    if result.returncode == 0:
        raise AssertionError(f"{label}: builder unexpectedly accepted invalid state")


def clone(destination: Path) -> Path:
    source = destination / "source"
    result = command(["git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(source)], ROOT)
    if result.returncode:
        raise AssertionError(f"temporary local clone failed: {result.stderr}")
    return source


def run_green_contract() -> None:
    with tempfile.TemporaryDirectory(prefix="msgriver-projection-selftest-") as temporary:
        root = Path(temporary)
        clean = clone(root / "clean")
        must_materialize(clean, root / "clean-output")

        malformed = clone(root / "malformed")
        manifest = malformed / MANIFEST_REL
        manifest.write_bytes(manifest.read_bytes() + b"README.md\n")
        must_reject(malformed, root / "malformed-output", "malformed manifest")

        omitted = clone(root / "omitted")
        lines = (omitted / MANIFEST_REL).read_text(encoding="utf-8").splitlines()
        (omitted / MANIFEST_REL).write_text(
            "\n".join(line for line in lines if line != "scripts/check_specs.py") + "\n",
            encoding="utf-8",
        )
        must_reject(omitted, root / "omitted-output", "required input omission")

        dirty = clone(root / "dirty")
        readme = dirty / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\n")
        must_reject(dirty, root / "dirty-output", "dirty tracked source")

        source_link = clone(root / "source-link")
        readme = source_link / "README.md"
        readme.unlink()
        readme.symlink_to("CODE_OF_CONDUCT.md")
        must_reject(source_link, root / "source-link-output", "source symlink")

        output_link = clone(root / "output-link")
        actual_parent = root / "actual-output-parent"
        actual_parent.mkdir()
        linked_parent = root / "linked-output-parent"
        linked_parent.symlink_to(actual_parent, target_is_directory=True)
        must_reject(output_link, linked_parent / "projection", "output symlink")

        source_drift = clone(root / "source-drift")
        drift_output = root / "source-drift-output"
        must_materialize(source_drift, drift_output)
        readme = source_drift / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\n")
        must_reject(source_drift, drift_output, "source byte drift", verify=True)

        output_extra = clone(root / "output-extra")
        extra_output = root / "output-extra-output"
        must_materialize(output_extra, extra_output)
        (extra_output / "unexpected.txt").write_text("extra\n", encoding="utf-8")
        must_reject(output_extra, extra_output, "output extra", verify=True)

        output_drift = clone(root / "output-drift")
        drift_output = root / "output-drift-output"
        must_materialize(output_drift, drift_output)
        readme = drift_output / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\n")
        must_reject(output_drift, drift_output, "output byte drift", verify=True)


def main() -> int:
    errors: list[str] = []
    entries = validate_manifest(ROOT, errors)
    for entry in entries:
        if entry == BUILDER_REL:
            continue
        try:
            mode = os.lstat(ROOT / entry).st_mode
        except OSError:
            fail(errors, f"listed source is missing: {entry}")
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            fail(errors, f"listed source is not regular: {entry}")
    if errors:
        print(f"public-projection-selftest: {len(errors)} contract violation(s)")
        return 2
    builder_path = ROOT / BUILDER_REL
    if not builder_path.is_file() or builder_path.is_symlink():
        print(RED_MESSAGE)
        return 1
    try:
        run_green_contract()
    except (AssertionError, OSError) as error:
        print(f"FAIL: {error}")
        return 2
    print("public-projection-selftest: GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
