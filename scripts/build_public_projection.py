#!/usr/bin/env python3
"""Task 0316 builder for the reproducible public-source projection.

Materialize mode proves every manifest path is a tracked HEAD blob that is
byte-identical to the source worktree, copies only those paths into a private
sibling staging directory, re-verifies the staged bytes, and renames staging to
the final output only after that succeeds. Verify mode repeats the source
proofs and checks an existing output tree for exact path-set and byte equality
without writing anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MANIFEST_REL = "release/publication/public-source-files.txt"
REGULAR_TREE_MODES = frozenset({"100644", "100755"})


def fail(errors: list[str], message: str) -> None:
    errors.append(message)
    print(f"ERROR: {message}")


def real_directory_chain(root: Path, label: str, errors: list[str]) -> bool:
    chain: list[Path] = []
    current = root
    while True:
        chain.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    for component in reversed(chain):
        try:
            mode = os.lstat(component).st_mode
        except OSError:
            fail(errors, f"{label} path component is missing: {component}")
            return False
        if stat.S_ISLNK(mode):
            fail(errors, f"{label} path component is a symlink: {component}")
            return False
        if not stat.S_ISDIR(mode):
            fail(errors, f"{label} path component is not a directory: {component}")
            return False
    return True


def check_ancestor_directories(
    source: Path, parts: list[str], kind: str, name: str, errors: list[str], checked: set[str]
) -> bool:
    current = source
    for part in parts[:-1]:
        current = current / part
        token = os.fspath(current)
        if token in checked:
            continue
        try:
            mode = os.lstat(current).st_mode
        except OSError:
            fail(errors, f"{kind} is missing: {name}")
            return False
        if stat.S_ISLNK(mode):
            fail(errors, f"{kind} has a symlinked ancestor: {name}")
            return False
        if not stat.S_ISDIR(mode):
            fail(errors, f"{kind} has a non-directory ancestor: {name}")
            return False
        checked.add(token)
    return True


def load_manifest(source: Path, errors: list[str]) -> list[str] | None:
    parts = MANIFEST_REL.split("/")
    if not check_ancestor_directories(source, parts, "manifest", MANIFEST_REL, errors, set()):
        return None
    path = source / MANIFEST_REL
    try:
        mode = os.lstat(path).st_mode
        data = path.read_bytes()
    except OSError:
        fail(errors, "manifest is unreadable")
        return None
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        fail(errors, "manifest must be a regular non-symlink file")
        return None
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        fail(errors, "manifest must be UTF-8")
        return None
    if b"\r" in data:
        fail(errors, "manifest must be LF-only")
        return None
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        fail(errors, "manifest must end with exactly one newline")
        return None
    lines = data.split(b"\n")[:-1]
    for number, line in enumerate(lines, 1):
        if not line:
            fail(errors, f"manifest line {number} is empty")
            continue
        entry = line.decode("utf-8", "replace")
        if entry.startswith("/") or any(part in ("", ".", "..") for part in entry.split("/")):
            fail(errors, f"manifest line {number} is not a normalized relative POSIX path")
    if lines != sorted(lines):
        fail(errors, "manifest is not in strict bytewise lexical order")
    if len(set(lines)) != len(lines):
        fail(errors, "manifest contains duplicate paths")
    if errors:
        return None
    return [line.decode("utf-8") for line in lines]


def head_blob_map(source: Path, errors: list[str]) -> dict[bytes, str] | None:
    result = subprocess.run(
        ["git", "-C", os.fspath(source), "ls-tree", "-r", "-z", "HEAD"],
        text=False,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        fail(errors, f"cannot list HEAD tree (git ls-tree exit {result.returncode})")
        return None
    blobs: dict[bytes, str] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        header, separator, raw_path = record.partition(b"\t")
        mode, kind, oid = header.split(b" ")
        if kind == b"blob":
            blobs[raw_path] = f"{mode.decode('ascii')} {oid.decode('ascii')}"
    return blobs


def hash_algorithm(source: Path) -> str:
    result = subprocess.run(
        ["git", "-C", os.fspath(source), "rev-parse", "--show-object-format"],
        text=True,
        capture_output=True,
        check=False,
    )
    algorithm = result.stdout.strip()
    return algorithm if algorithm in ("sha1", "sha256") else "sha1"


def blob_digest(algorithm: str, data: bytes) -> str:
    digest = hashlib.new(algorithm)
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def validate_entry(
    source: Path,
    entry: str,
    blobs: dict[bytes, str],
    algorithm: str,
    errors: list[str],
    checked: set[str],
) -> bool:
    if not check_ancestor_directories(source, entry.split("/"), "listed source", entry, errors, checked):
        return False
    path = source / entry
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        fail(errors, f"listed source is missing: {entry}")
        return False
    if stat.S_ISLNK(mode):
        fail(errors, f"listed source is a symlink: {entry}")
        return False
    if not stat.S_ISREG(mode):
        fail(errors, f"listed source is not a regular file: {entry}")
        return False
    tracked = blobs.get(entry.encode("utf-8"))
    if tracked is None:
        fail(errors, f"listed source is not a tracked HEAD path: {entry}")
        return False
    tree_mode, oid = tracked.split(" ")
    if tree_mode not in REGULAR_TREE_MODES:
        fail(errors, f"listed source is not tracked at HEAD as a regular file: {entry}")
        return False
    try:
        data = path.read_bytes()
    except OSError:
        fail(errors, f"listed source is unreadable: {entry}")
        return False
    if blob_digest(algorithm, data) != oid:
        fail(errors, f"listed source differs from HEAD: {entry}")
        return False
    return True


def manifest_directories(entries: list[str]) -> set[str]:
    required: set[str] = set()
    for entry in entries:
        parts = entry.split("/")
        for index in range(1, len(parts)):
            required.add("/".join(parts[:index]))
    return required


def verify_tree(
    root: Path, source: Path, entries: list[str], label: str, errors: list[str]
) -> None:
    expected = set(entries)
    files: set[str] = set()
    directories: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        for name in dirnames:
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            directories.add(relative)
            try:
                mode = os.lstat(path).st_mode
            except OSError:
                fail(errors, f"{label} entry is unreadable: {relative}")
                continue
            if stat.S_ISLNK(mode):
                fail(errors, f"{label} entry is a symlink: {relative}")
            elif not stat.S_ISDIR(mode):
                fail(errors, f"{label} entry is not a directory: {relative}")
        for name in filenames:
            path = Path(dirpath) / name
            relative = path.relative_to(root).as_posix()
            try:
                mode = os.lstat(path).st_mode
            except OSError:
                fail(errors, f"{label} entry is unreadable: {relative}")
                continue
            files.add(relative)
            if stat.S_ISLNK(mode):
                fail(errors, f"{label} entry is a symlink: {relative}")
            elif not stat.S_ISREG(mode):
                fail(errors, f"{label} entry is not a regular file: {relative}")
    for relative in sorted(directories - manifest_directories(entries)):
        fail(errors, f"{label} contains an extra directory: {relative}")
    for relative in sorted(files - expected):
        fail(errors, f"{label} contains an extra file: {relative}")
    for entry in sorted(expected - files):
        fail(errors, f"{label} omits manifest path: {entry}")
    for entry in sorted(expected & files):
        try:
            if (root / entry).read_bytes() != (source / entry).read_bytes():
                fail(errors, f"{label} differs from source: {entry}")
        except OSError:
            fail(errors, f"{label} entry is unreadable: {entry}")


def materialize(
    source: Path,
    output: Path,
    entries: list[str],
    blobs: dict[bytes, str],
    errors: list[str],
) -> bool:
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    try:
        for entry in entries:
            destination = staging / entry
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / entry, destination)
                tree_mode = blobs[entry.encode("utf-8")].split(" ")[0]
                os.chmod(destination, 0o755 if tree_mode == "100755" else 0o644)
            except OSError:
                fail(errors, f"cannot copy listed source: {entry}")
                return False
        verify_tree(staging, source, entries, "staged projection", errors)
        if errors:
            return False
        try:
            os.lstat(output)
        except OSError:
            pass
        else:
            fail(errors, f"output path already exists: {output}")
            return False
        try:
            os.rename(staging, output)
        except OSError:
            fail(errors, f"cannot atomically publish output: {output}")
            return False
        return True
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def run(source: Path, output: Path, verify: bool) -> int:
    errors: list[str] = []
    if not real_directory_chain(source, "source", errors):
        return 1
    entries = load_manifest(source, errors)
    if entries is None:
        return 1
    blobs = head_blob_map(source, errors)
    if blobs is None:
        return 1
    algorithm = hash_algorithm(source)
    checked: set[str] = set()
    for entry in entries:
        validate_entry(source, entry, blobs, algorithm, errors, checked)
    if errors:
        return 1
    if verify:
        if not real_directory_chain(output, "output", errors):
            return 1
        verify_tree(output, source, entries, "output", errors)
        if errors:
            return 1
        print(f"public-projection: verified {len(entries)} files at {output}")
        return 0
    if not real_directory_chain(output.parent, "output parent", errors):
        return 1
    try:
        os.lstat(output)
    except OSError:
        pass
    else:
        fail(errors, f"output path already exists: {output}")
        return 1
    if not materialize(source, output, entries, blobs, errors):
        return 1
    print(f"public-projection: materialized {len(entries)} files at {output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Materialize or verify the public-source projection"
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    arguments = parser.parse_args()
    source = Path(os.path.abspath(arguments.source))
    output = Path(os.path.abspath(arguments.output))
    return run(source, output, arguments.verify)


if __name__ == "__main__":
    sys.exit(main())
