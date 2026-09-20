#!/usr/bin/python3
"""Task 0008 test-only supervisor; never publishes or recovers a key.

A root-owned tracer survives the worker's non-dumpable policy. Workers run in
an isolated network namespace. Trace writes contain addresses/counts only.
Only aggregate verdicts escape; raw traces and fixtures are removed after reap.
"""
import fcntl
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

NAMES = (
    ".initialization-journal-integrity.tmp",
    "initialization-journal-integrity.key",
    ".initialization-portable-reservation.tmp",
    "initialization-portable-reservation.key",
)
ROLES = {"j": "JournalIntegrity", "r": "PortableReservation"}
OPS = {"create": "Create", "write": "Write", "file_sync": "FileSync",
       "rename": "Rename", "directory_sync": "DirectorySync"}
LIMIT = 12


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def metadata(root):
    result = {}
    for p in root.iterdir():
        m = p.lstat()
        result[p.name] = (m.st_dev, m.st_ino, m.st_mode, m.st_nlink,
                          m.st_size, m.st_mtime_ns,
                          os.readlink(p) if stat.S_ISLNK(m.st_mode) else None)
    return result


def prefix_files(case):
    _, role, op, phase = case.split(":")
    base = 0 if role == "j" else 2
    files = {NAMES[1]: 32} if role == "r" else {}
    completed = list(OPS).index(op) + (phase == "after")
    if completed:
        files[NAMES[base + (completed >= 4)]] = 32 if completed >= 2 else 0
    return files


def check_prefix(root, case):
    entries = metadata(root)
    require("msgriver.lock" in entries, "interruption omitted owner lock")
    entries.pop("msgriver.lock")
    wanted = prefix_files(case)
    require(set(entries) == set(wanted), "interruption prefix names")
    for name, size in wanted.items():
        _, _, mode, links, length, _, _ = entries[name]
        require(stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o600,
                "interruption prefix type/mode")
        require(links == 1 and length == size, "interruption prefix width/links")


def empty_metadata_path(line, fixture_base, root_fd):
    """Return only the permitted second-argument quote position, if any."""
    match = re.fullmatch(
        r'(statx|newfstatat)\(([0-9]+)<([^<>"\n]+)>, (""), (.*)\)\s+= .+', line)
    if match is None:
        return None
    syscall, descriptor, path, _, tail = match.groups()
    roots = (fixture_base + '/state', fixture_base + '/state.anchored')
    if not ((root_fd is not None and int(descriptor) == root_fd and path in roots)
            or path in tuple(root + '/msgriver.lock' for root in roots)):
        return None
    # statx flags are argument 3; newfstatat flags are argument 4, after a
    # possibly nested metadata struct. Commas inside that struct are not args.
    arguments, stack, start = [], [], 0
    for index, char in enumerate(tail):
        if char in '"<>':
            return None
        if char in '{[(':
            stack.append(char)
        elif char in '}])':
            if not stack or stack.pop() != {'}': '{', ']': '[', ')': '('}[char]:
                return None
        elif char == ',' and not stack:
            arguments.append(tail[start:index].strip())
            start = index + 1
    arguments.append(tail[start:].strip())
    if stack or len(arguments) != (3 if syscall == 'statx' else 2):
        return None
    flags = arguments[0 if syscall == 'statx' else 1].split('|')
    if ('AT_EMPTY_PATH' not in flags
            or not all(re.fullmatch(r'[A-Z][A-Z0-9_]*|0x[0-9a-f]+|[0-9]+', flag)
                       for flag in flags)):
        return None
    return match.start(4)


def exact_write_limit(line, fd, count):
    """Recognize one strace write with the injected completed width.

    strace renders nonzero byte counts in hexadecimal here, but renders zero
    as decimal `0`.  Both positions must use the same permitted spelling.
    """
    spelling = r'(?:0x0|0)' if count == 0 else re.escape(hex(count))
    return re.search(
        r'\bwrite\(' + re.escape(hex(fd)) + r', .*?, ' + spelling
        + r'\)\s+= ' + spelling + r'$', line,
    ) is not None


def audit(lines, case, interrupted=False):
    """Independent syscall oracle. Hook events delimit, but do not satisfy, I/O.

    No payload is decoded. Descriptor-relative key operations and real barriers
    are checked between their Before/After notifications, even at kill prefixes.
    Test fixture creation for a race uses one explicitly allowed absolute path.
    """
    active = False
    step = None
    calls = []
    root_fd = None
    root_reference_fds = set()
    key_fds = {}
    root_opens = 0
    completed = []
    source_calls = 0
    scope = []
    fixture_base = None
    parts = case.split(":")
    race_path = None
    if parts[0] == "race":
        index = (0 if parts[1] == "j" else 2) + (parts[2] == "rename")
        race_path = NAMES[index]

    def verify(boundary, operations):
        nonlocal root_fd, root_opens
        if boundary == "OpenRoot":
            opens = [line for line in operations if re.search(r'open(?:at|at2)?\(', line)
                     and 'O_DIRECTORY' in line and re.search(r'= \d+<', line)]
            require(len(opens) == 1, "single root descriptor open")
            require("O_NOFOLLOW" in opens[0], "root no-follow open")
            root_fd = int(re.search(r'= (\d+)<', opens[0])[1])
            root_opens += 1
            return
        if boundary.startswith("Preflight"):
            index = int(re.search(r'\((\d)\)', boundary)[1])
            probes = [line for line in operations if '"' + NAMES[index] + '"' in line]
            require(len(probes) == 1 and re.search(r'\b(?:newfstatat|statx)\(' + str(root_fd) + r'<', probes[0])
                    and 'AT_SYMLINK_NOFOLLOW' in probes[0]
                    and 'ENOENT' in probes[0], "descriptor no-follow preflight")
            return
        match = re.fullmatch(r'(Create|Write|FileSync|Rename|DirectorySync)\((\w+)\)', boundary)
        if not match:
            return
        op, role = match.groups()
        base = 0 if role == ROLES["j"] else 2
        temp, final = NAMES[base:base + 2]
        if op == "Create":
            actual = [line for line in operations if f'"{temp}"' in line
                      and re.search(r'openat(?:2)?\(', line)]
            require(len(actual) == 1, "exactly one temporary creation")
            line = actual[0]
            require(re.search(r'openat\(' + str(root_fd) + r'<', line), "relative create dirfd")
            require(all(flag in line for flag in ("O_EXCL", "O_CREAT", "O_NOFOLLOW")),
                    "exclusive no-follow create")
            require("O_TRUNC" not in line, "temporary truncation")
            fd = re.search(r'= (\d+)<', line)
            require(fd is not None, "temporary open failed before After")
            key_fds[role] = int(fd[1])
        elif op == "Write":
            fd = key_fds.get(role)
            writes = [line for line in operations if re.search(r'\bwrite\(' + hex(fd) + r',', line)]
            require(len(writes) == 1, "one non-retried write")
            require(re.search(r', 0x20\)\s+= 0x20$', writes[0]), "complete raw32 write")
        elif op == "FileSync":
            fd = key_fds.get(role)
            require(sum(bool(re.search(r'\bfsync\(' + str(fd) + r'<.*\)\s+= 0$', line))
                        for line in operations) == 1, "real file fsync")
        elif op == "Rename":
            renames = [line for line in operations if 'rename' in line and f'"{temp}"' in line]
            require(len(renames) == 1, "single rename")
            line = renames[0]
            require(re.search(r'\brenameat2\(' + str(root_fd) + r'<', line)
                    and f'"{final}"' in line and "RENAME_NOREPLACE" in line
                    and len(re.findall(str(root_fd) + r'<', line)) == 2
                    and line.endswith("= 0"), "same-dirfd atomic no-replace rename")
        else:
            require(sum(bool(re.search(r'\bfsync\(' + str(root_fd) + r'<.*\)\s+= 0$', line))
                        for line in operations) == 1, "real parent fsync")

    for raw in lines:
        line = re.sub(r'^\d+\s+', '', raw.strip())
        if '"' in line and '/scope-begin"' in line and 'openat(' in line:
            active = True
            match = re.search(r'"([^"\n]+)/signals-\d+/scope-begin"', line)
            require(match is not None, "scope fixture identity")
            fixture_base = match[1]
        elif '"' in line and '/scope-end"' in line and 'openat(' in line:
            active = False
        if not active:
            continue
        scope.append(line)
        require(not re.search(r'\b(socket|connect|sendto|sendmsg|bind|listen|accept|socketpair)\(', line),
                "network operation during publication")
        require(not re.search(r'\b(?:write|writev|pwrite64)\(0x[12],', line),
                "publication wrote stdout/stderr")
        if 'getrandom(' in line:
            source_calls += 1
        # A-14.3 permits the fixed root pathname only while resolving the
        # identity-only reference.  Every later lock operation must use that
        # one O_PATH descriptor and the fixed basename.
        if (fixture_base is not None and 'O_PATH' in line
                and any(f'"{root}"' in line for root in
                        (fixture_base + '/state', fixture_base + '/state.anchored'))):
            fd = re.search(r'= (\d+)<', line)
            require(fd is not None, "root identity reference descriptor")
            root_reference_fds.add(int(fd[1]))
        # Hook-free production has no OpenRoot callback.  Learn its retained
        # descriptor from the actual open before examining later relative key
        # calls; `verify(OpenRoot, ...)` below still enforces the single open.
        if (parts[0] == 'production' and root_fd is None and 'O_DIRECTORY' in line
                and re.search(r'\bopenat\(', line)):
            fd = re.search(r'= (\d+)<', line)
            require(fd is not None, "production root descriptor")
            root_fd = int(fd[1])
        # Every key path used by production is a basename relative to one fd.
        # The sole absolute key-path exception is the deliberate race fixture.
        metadata_quote = empty_metadata_path(line, fixture_base, root_fd)
        for quoted_match in re.finditer(r'"([^"]*)"', line):
            quoted = quoted_match[1]
            if quoted == '' and quoted_match.start() == metadata_quote:
                continue
            allowed_absolute = quoted in (fixture_base + '/state', fixture_base + '/state.anchored')
            allowed_signal = quoted.startswith(fixture_base + '/signals-')
            allowed_race = parts[0] == 'race' and quoted in (
                fixture_base + '/state/' + race_path, fixture_base + '/target')
            allowed_lock = quoted == 'msgriver.lock'
            require(quoted in NAMES or allowed_absolute or allowed_signal or allowed_race or allowed_lock,
                    "unexpected path effect during publication")
            if allowed_lock:
                require(root_reference_fds
                        and any(re.search(r'\(' + str(fd) + r'<', line)
                                for fd in root_reference_fds),
                        "lock operation not relative to root identity reference")
            if quoted in NAMES:
                require(root_fd is not None and re.search(r'\(' + str(root_fd) + r'<', line),
                        "key operation not relative to retained directory")
            for name in NAMES:
                if quoted.endswith('/' + name):
                    require(parts[0] == 'race' and name == race_path,
                            "pathname key access or existing-entry read")
        boundary = re.search(r'/boundary-([^"/]+)-(Before|After)"', line)
        if boundary and 'openat(' in line:
            name, phase = boundary.groups()
            if phase == "Before":
                step, calls = name, []
            else:
                require(step == name, "unpaired syscall boundary")
                verify(name, calls)
                completed.append(name)
                step, calls = None, []
        elif step:
            calls.append(line)
        # Existing names may be statted, never opened/read during preflight.
        if step and step.startswith('Preflight'):
            require(not (re.search(r'\bopen(?:at|at2)?\(', line)
                         and any('"' + name + '"' in line for name in NAMES)),
                    "preflight opened an existing entry")
    require(scope, "missing syscall scope")
    if parts[0] == 'production':
        # No hooks exist on the production entry: reconstruct boundaries from
        # the real syscalls, and require the same independently ordered chain.
        roots = [(i, line) for i, line in enumerate(scope) if 'O_DIRECTORY' in line
                 and re.search(r'\bopenat\(', line) and re.search(r'= \d+<', line)]
        require(len(roots) == 1, "production single root open")
        position, line = roots[0]
        verify('OpenRoot', [line])
        for index, name in enumerate(NAMES):
            probes = [(i, line) for i, line in enumerate(scope) if '"' + name + '"' in line
                      and re.search(r'\b(newfstatat|statx)\(', line)]
            require(len(probes) == 1 and probes[0][0] > position, "production ordered preflight")
            position = probes[0][0]
            verify(f'Preflight({index})', [probes[0][1]])
        samples = [(i, line) for i, line in enumerate(scope) if 'getrandom(' in line]
        require(len(samples) == 2 and samples[0][0] > position, "production two entropy calls after preflight")
        require(all(re.search(r', 0x20, 0\)\s+= 0x20$', line) for _, line in samples), "production exact OS samples")
        position = samples[-1][0]
        for role, base in ((ROLES['j'], 0), (ROLES['r'], 2)):
            for op in OPS.values():
                candidates = []
                for i in range(position + 1, len(scope)):
                    line = scope[i]
                    if op == 'Create':
                        match = 'openat(' in line and '"' + NAMES[base] + '"' in line
                    elif op == 'Write':
                        match = bool(re.search(r'\bwrite\(' + hex(key_fds[role]) + r',', line))
                    elif op == 'Rename':
                        match = 'rename' in line and '"' + NAMES[base] + '"' in line
                    else:
                        fd = key_fds[role] if op == 'FileSync' else root_fd
                        match = bool(re.search(r'\bfsync\(' + str(fd) + r'<', line))
                    if match:
                        candidates.append((i, line))
                require(candidates, "production omitted publication operation")
                position, line = candidates[0]
                verify(op + '(' + role + ')', [line])
    # Root opens in the marked production window must occur once; lock-probe
    # opens are of msgriver.lock and do not count as directory opens.  The
    # hook-free production path reconstructs OpenRoot immediately above.
    if root_fd is not None:
        require(root_opens == 1, "root reopened")
        opens = [line for line in scope if re.search(r'\bopen(?:at|at2)?\(', line)
                 and 'O_DIRECTORY' in line and re.search(r'= \d+<', line)]
        require(len(opens) == 1, "extra directory open during publication")
    if parts[0] != 'production':
        require(source_calls == 0, "duplicate OS entropy on injected path")
    if parts[0] in ('success', 'swapped', 'rebind', 'fresh_restart'):
        require(completed[-1:] == ['DirectorySync(PortableReservation)'], "success before second parent barrier")
    if parts[0] == 'short':
        role = ROLES[parts[1]]
        fd = key_fds.get(role)
        require(fd is not None, "short write missing temporary descriptor")
        writes = [line for line in calls if re.search(r'\bwrite\(' + hex(fd) + r',', line)]
        require(len(writes) == 1, "short write retried or fabricated")
        n = int(parts[3])
        require(exact_write_limit(writes[0], fd, n),
                "write limit did not perform actual short write")
    if interrupted:
        target = OPS[parts[2]] + '(' + ROLES[parts[1]] + ')'
        if parts[3] == 'after':
            require(completed[-1:] == [target], "wrong after interruption checkpoint")
        else:
            require(step == target, "wrong before interruption checkpoint")


class Supervisor:
    def __init__(self, binary, worker, base, uid, gid):
        self.binary, self.worker, self.base = binary, worker, base
        self.uid, self.gid = uid, gid
        self.children = []
        self.counter = 0

    def start(self, case, root, traced=True):
        self.counter += 1
        signals = self.base / f'signals-{self.counter}'
        signals.mkdir(mode=0o700)
        os.chown(signals, self.uid, self.gid)
        trace = self.base / f'trace-{self.counter}'
        output = self.base / f'output-{self.counter}'
        env = dict(os.environ, MSGRIVER_PUBLICATION_CASE=case,
                   MSGRIVER_PUBLICATION_ROOT=str(root),
                   MSGRIVER_PUBLICATION_SIGNALS=str(signals),
                   MSGRIVER_PUBLICATION_UID=str(self.uid))
        uid = 0 if case == 'root' else self.uid
        command = ['/usr/bin/unshare', '--net', '/usr/bin/python3', __file__,
                   '--worker', str(uid), str(self.gid), self.binary, self.worker]
        if traced:
            command = ['/usr/bin/strace', '-f', '-qq', '-yy', '-s', '0',
                       '-e', 'trace=%file,fsync,fdatasync,write,writev,pwrite64,flock,%network,getrandom',
                       '-e', 'raw=write,writev,pwrite64,getrandom', '-o', str(trace)] + command
        with output.open('wb') as stream:
            child = subprocess.Popen(command, env=env, stdout=stream, stderr=stream,
                                     start_new_session=True)
        item = child, signals, trace, output
        self.children.append(item)
        return item

    def wait_marker(self, item, name):
        child, signals, _, _ = item
        deadline = time.monotonic() + LIMIT
        while time.monotonic() < deadline:
            if (signals / name).exists() and (signals / name).stat().st_size > 0:
                return
            if child.poll() is not None:
                self.result(item)
                raise AssertionError('worker exited before checkpoint')
            time.sleep(.01)
        raise AssertionError('worker checkpoint timeout')

    def result(self, item):
        child, signals, trace, output = item
        child.wait(timeout=LIMIT)
        if (signals / 'missing').exists():
            require(child.returncode != 0 and (signals / 'scope-begin').exists()
                    and (signals / 'scope-end').exists()
                    and not (signals / 'continued').exists(), 'invalid missing frontier terminal')
            # The causal failure must not conceal a fixture or unrelated panic.
            terminal = output.read_bytes()
            require(terminal.count(b"panicked at") == 1
                    and b'MissingPublication: initialization_key_pair_publication' in terminal,
                    'unrelated worker failure')
            raise MissingPublication()
        require(child.returncode == 0 and (signals / 'passed').exists(), 'worker contract failure')
        return trace.read_text().splitlines()

    def kill_reap(self, item):
        child, signals, _, _ = item
        pid = int((signals / 'ready').read_text())
        os.kill(pid, signal.SIGKILL)
        child.wait(timeout=LIMIT)
        require(not Path(f'/proc/{pid}').exists(), 'worker not reaped')
        require(not (signals / 'continued').exists(), 'interrupted worker continued')

    def cleanup(self):
        for child, signals, _, _ in self.children:
            if child.poll() is None:
                ready = signals / 'ready'
                if ready.exists():
                    try:
                        os.kill(int(ready.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=LIMIT)
                    except subprocess.TimeoutExpired:
                        pass
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=LIMIT)
        shutil.rmtree(self.base)


class MissingPublication(Exception):
    pass


def main():
    binary, worker, base, case, uid, gid = sys.argv[1:]
    base, uid, gid = Path(base), int(uid), int(gid)
    require(os.geteuid() == 0 and uid != 0, 'root supervisor/non-root worker prerequisites')
    require(base.is_dir() and base.name.startswith('msgriver-publication-red-'), 'fixture root')
    root = base / 'state'
    root.mkdir(mode=0o700)
    os.chown(root, uid, gid)
    target = base / 'target'
    target.write_bytes(b'public-fixture')
    os.chown(target, uid, gid)
    target.chmod(0o600)
    supervisor = Supervisor(binary, worker, base, uid, gid)
    lock = None
    try:
        # Real root-owned kill/reap control runs before every causal RED call.
        control = supervisor.start('supervision', root, traced=False)
        supervisor.wait_marker(control, 'paused')
        supervisor.kill_reap(control)
        if case == 'contender':
            lock = os.open(root / 'msgriver.lock', os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.fchown(lock, uid, gid)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        item = supervisor.start(case, root)
        if case.startswith('interrupt:'):
            supervisor.wait_marker(item, 'paused')
            require((item[1] / 'paused').read_text() == OPS[case.split(':')[2]] + '(' + ROLES[case.split(':')[1]] + ')/' + case.split(':')[3].title(), 'checkpoint identity')
            check_prefix(root, case)
            # The real second process must lose without entropy/key effects.
            contender = supervisor.start('contender', root)
            audit(supervisor.result(contender), 'contender')
            supervisor.kill_reap(item)
            audit(item[2].read_text().splitlines(), case, interrupted=True)
            check_prefix(root, case)
            before = metadata(root)
            restart_case = 'restart' if prefix_files(case) else 'fresh_restart'
            restarted = supervisor.start(restart_case, root)
            audit(supervisor.result(restarted), restart_case)
            if restart_case == 'restart':
                require(metadata(root) == before, 'restart changed surviving prefix')
        else:
            audit(supervisor.result(item), case)
        print('PASS: supervised publication contract')
        return 0
    except MissingPublication:
        print('MissingPublication: initialization_key_pair_publication; supervision-control=kill/reaped')
        return 1
    except (AssertionError, OSError, subprocess.TimeoutExpired):
        # Details may include paths/buffers; retain only the failure category.
        print('FAIL: publication supervisor/contract assertion')
        return 2
    finally:
        if lock is not None:
            os.close(lock)
        supervisor.cleanup()


if __name__ == '__main__':
    if sys.argv[1:2] == ['--worker']:
        uid, gid = map(int, sys.argv[2:4])
        os.setgroups([])
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
        os.umask(0)
        os.execv(sys.argv[4], [sys.argv[4], '--exact', sys.argv[5], '--nocapture', '--test-threads=1'])
    sys.exit(main())
