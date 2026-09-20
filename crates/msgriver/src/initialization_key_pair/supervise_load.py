#!/usr/bin/python3
"""Task 0014 root-owned fixture supervisor; never reads or exports key bytes."""
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys

FINALS = ("initialization-journal-integrity.key", "initialization-portable-reservation.key")
TEMPS = (".initialization-journal-integrity.tmp", ".initialization-portable-reservation.tmp")


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def fixture(root, case, uid, gid):
    journal = bytes([0x35]) * 32
    reservation = bytes([0xa9]) * 32
    missing = "j" if case == "missing-j" else "r" if case == "missing-r" else None
    for index, name in enumerate(FINALS):
        if missing == ("j" if index == 0 else "r"):
            continue
        value = journal if index == 0 else reservation
        if case == "zero-" + ("j" if index == 0 else "r"):
            value = bytes(32)
        if case == "short-" + ("j" if index == 0 else "r"):
            value = value[:-1]
        if case == "oversized-" + ("j" if index == 0 else "r"):
            value += bytes([0x01])
        if case == "equal" and index == 1:
            value = journal
        path = root / name
        path.write_bytes(value)
        os.chown(path, uid, gid)
        path.chmod(0o600)
    if case.startswith("temporary-"):
        index = 0 if case.endswith("j") else 1
        path = root / TEMPS[index]
        path.write_bytes(b"fixture")
        os.chown(path, uid, gid)
        path.chmod(0o600)
    if case.startswith("unsafe-"):
        _, role, kind = case.split("-", 2)
        index = 0 if role == "j" else 1
        path = root / FINALS[index]
        path.unlink()
        if kind == "symlink":
            os.symlink(root.parent / "target", path)
        elif kind == "directory":
            path.mkdir(0o700)
            os.chown(path, uid, gid)
        elif kind == "fifo":
            os.mkfifo(path, 0o600)
            os.chown(path, uid, gid)
        elif kind == "socket":
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            os.chown(path, uid, gid)
            return listener
        elif kind == "device":
            os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(1, 3))
            os.chown(path, uid, gid)
        elif kind == "hardlink":
            target = root.parent / "target"
            target.write_bytes(b"fixture")
            os.chown(target, uid, gid)
            target.chmod(0o600)
            os.link(target, path)
        elif kind == "mode":
            path.write_bytes(journal)
            os.chown(path, uid, gid)
            path.chmod(0o640)
        elif kind == "owner":
            path.write_bytes(journal)
            path.chmod(0o600)
        else:
            raise AssertionError("unknown unsafe fixture")
    return None


def audit_success(trace, signals):
    """Verify the green loader's actual descriptor-relative read protocol.

    Hook events delimit the call but do not count as I/O proof. No key payload
    is decoded: this oracle reads only syscall names, basenames, descriptors,
    and byte counts.
    """
    active, scope = False, []
    for raw in trace.read_text().splitlines():
        line = re.sub(r"^\d+\s+", "", raw.strip())
        if "scope-begin" in line and "openat(" in line:
            active = True
        if active:
            scope.append(line)
        if "scope-end" in line and "openat(" in line:
            active = False
    require(scope and not active, "bounded syscall scope")
    directory_opens = [line for line in scope if "openat(" in line and "O_DIRECTORY" in line
                       and "O_NOFOLLOW" in line and re.search(r"= \d+<", line)]
    require(len(directory_opens) == 1, "one readable root descriptor")
    root_fd = int(re.search(r"= (\d+)<", directory_opens[0])[1])
    all_names = FINALS + TEMPS
    for line in scope:
        for name in all_names:
            if '"' + name + '"' in line:
                require(re.search(r"\(" + str(root_fd) + r"<", line) is not None,
                        "key operation is relative to retained descriptor")
            require('"/' + name + '"' not in line, "absolute key pathname")
    key_opens = []
    for name in FINALS:
        opens = [(index, line) for index, line in enumerate(scope)
                 if "openat(" in line and '"' + name + '"' in line]
        require(len(opens) == 1, "one final-key open")
        open_index, line = opens[0]
        require("O_NOFOLLOW" in line and "O_RDONLY" in line, "read-only no-follow key open")
        descriptor = re.search(r"= (\d+)<", line)
        require(descriptor is not None, "key open descriptor")
        key_opens.append((name, open_index, int(descriptor[1])))
    key_opens.sort(key=lambda item: item[1])
    for position, (name, open_index, fd) in enumerate(key_opens):
        end = key_opens[position + 1][1] if position + 1 < len(key_opens) else len(scope)
        fd_pattern = r"(?:" + str(fd) + r"|0x" + format(fd, "x") + r")(?:<[^>]+>)?"
        reads = [line for line in scope[open_index + 1:end]
                 if re.search(r"\bread\(" + fd_pattern + r",", line)]
        require(len(reads) == 2, "one raw32 read plus EOF probe")
        require(re.search(r", (?:0x20|32)\)\s+=\s+(?:0x20|32)$", reads[0]) is not None,
                "exact raw32 read")
        require(re.search(r", (?:0x1|1)\)\s+=\s+0$", reads[1]) is not None,
                "exact EOF proof")
        require(not any(re.search(r"\b(?:write|pwrite64|rename|unlink)\(" + fd_pattern + r",", line)
                        for line in scope[open_index + 1:end]), "loader modified a key descriptor")


def main():
    binary, worker, base, case, uid, gid = sys.argv[1:]
    base, uid, gid = Path(base), int(uid), int(gid)
    require(os.geteuid() == 0 and uid != 0, "root supervisor/non-root worker prerequisites")
    require(base.is_dir() and base.name.startswith("msgriver-load-red-"), "fixture root")
    root = base / "state"
    root.mkdir(mode=0o700)
    os.chown(root, uid, gid)
    signals = base / "signals"
    signals.mkdir(mode=0o700)
    os.chown(signals, uid, gid)
    listener = None
    try:
        listener = fixture(root, case, uid, gid)
        env = dict(os.environ, MSGRIVER_LOAD_CASE=case, MSGRIVER_LOAD_ROOT=str(root),
                   MSGRIVER_LOAD_SIGNALS=str(signals))
        command = ["/usr/bin/unshare", "--net", "/usr/bin/python3", __file__, "--worker",
                   str(uid), str(gid), binary, worker]
        trace = base / "trace"
        command = ["/usr/bin/strace", "-f", "-qq", "-yy", "-s", "0",
                   "-e", "trace=%file,read,write,pwrite64,rename,unlink,flock,fcntl",
                   "-e", "raw=read", "-o", str(trace)] + command
        result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=20, check=False)
        if (signals / "missing").exists():
            require(result.returncode != 0 and not (signals / "passed").exists(), "missing frontier terminal")
            require(b"MissingLoad: initialization_key_pair_load" in result.stdout, "wrong red frontier")
            print("FAIL: MissingLoad: initialization_key_pair_load")
            return 1
        require(result.returncode == 0 and (signals / "passed").exists(), "worker contract failure")
        if case in ("success", "rebind"):
            audit_success(trace, signals)
        print("PASS: supervised load contract")
        return 0
    finally:
        if listener is not None:
            listener.close()
        shutil.rmtree(base)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--worker"]:
        uid, gid = map(int, sys.argv[2:4])
        os.setgroups([])
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
        os.umask(0)
        os.execv(sys.argv[4], [sys.argv[4], "--exact", sys.argv[5], "--nocapture", "--test-threads=1"])
    sys.exit(main())
