"""strace log parser. Never raises on odd input; unknown lines are counted in parse_warnings.

Which syscalls are collected matters as much as how they are parsed: a call that is not traced cannot be detected.
`sandbox.STRACE_SYSCALLS` is built from the groups below so the tracer and the parser cannot drift apart."""
import re
from dataclasses import dataclass, field

from .models import Event

# ---- syscall groups: the single source of truth for what is collected and what each call means ----
OPEN_CALLS = ("open", "openat", "openat2", "creat")
EXEC_CALLS = ("execve", "execveat")
CONNECT_CALLS = ("connect",)
# sending a datagram with an explicit destination needs no connect(): these are network attempts too
SEND_CALLS = ("sendto", "sendmsg", "sendmmsg")
RENAME_LIKE = ("rename", "renameat", "renameat2", "link", "linkat")  # destination is the second path
SYMLINK_CALLS = ("symlink", "symlinkat")
PATH_MUTATORS = ("unlink", "unlinkat", "rmdir", "mkdir", "mkdirat", "chmod", "fchmodat", "fchmodat2", "chown",
                 "lchown", "fchownat", "truncate", "mknod", "mknodat")
CWD_CALLS = ("chdir", "fchdir")
# signals are common between pip's own subprocesses, so only those aimed at the sandbox init (pid 1) or at
# everything (-1) are findings; the call is still collected so that the target can be inspected
SIGNAL_CALLS = ("kill", "tkill", "tgkill")
SIGNAL_TARGETS = (1, -1)
SPAWN_CALLS = ("clone", "clone3", "fork", "vfork")
# calls with no legitimate use during an offline pip install; an attempt is a finding even when the kernel
# or seccomp refuses it (Docker's default profile denies most of these, which is exactly why attempts matter)
EVASION_CALLS = ("memfd_create", "io_uring_setup", "io_uring_enter", "io_uring_register", "ptrace", "process_vm_readv",
                 "process_vm_writev", "mount", "umount2", "pivot_root", "chroot", "unshare", "setns", "bpf",
                 "init_module", "finit_module", "delete_module", "keyctl", "kexec_load", "kexec_file_load")
# names newer than some strace builds: '?' tells strace to ignore a name it does not know instead of failing
OPTIONAL_CALLS = ("openat2", "fchmodat2", "clone3", "execveat", "kexec_file_load")

TRACED_SYSCALLS = tuple(dict.fromkeys(OPEN_CALLS + EXEC_CALLS + CONNECT_CALLS + SEND_CALLS + RENAME_LIKE
                                      + SYMLINK_CALLS + PATH_MUTATORS + CWD_CALLS + SPAWN_CALLS + EVASION_CALLS
                                      + SIGNAL_CALLS))


def strace_filter() -> str:
    return ",".join(("?" + s) if s in OPTIONAL_CALLS else s for s in TRACED_SYSCALLS)


LINE_RE = re.compile(r"^(?:(\d+)\s+)?(\d+\.\d+)\s+(.*)$")
CALL_RE = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(.*)$")
RESUMED_RE = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
UNFINISHED_SUFFIX = " <unfinished ...>"
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
FD_ANNOT_RE = re.compile(r"(?:AT_FDCWD|\d+)<([^>]*)>")
DIRFD_RE = re.compile(r"^\s*(?:AT_FDCWD|\d+)<([^>]*)>")
SPAWN_RE = re.compile(
    r"^(?:(\d+)\s+)?\d+\.\d+\s+(?:(?:clone3?|fork|vfork)\(.*\)|<\.\.\. (?:clone3?|fork|vfork) resumed>.*)\s+=\s+(\d+)\b")
INITIAL_CWD = "/work"
ROOT_PID = None  # key used for logs without pid prefixes (single-process traces)
TRUNCATED_RE = re.compile(r'"\.\.\.')  # strace marks a cut-off string as "abc"...


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    parse_warnings: int = 0
    lines: int = 0
    unresumed: int = 0  # '<unfinished ...>' calls that never resumed (lost events)
    truncated: int = 0  # records whose strings were cut off by strace (-s limit)
    root_pid: int | None = None
    root_exited: bool = False  # saw the exit notice of the first traced process
    # marker mode (tracer attached to the sandbox init): the init execs `final_exec` when the package command is done
    final_exec: str | None = None
    init_pid: int = 1  # the sandbox init: PID 1 of the package container's PID namespace
    final_exec_pid: int | None = None  # set only when the INIT ran `final_exec` (a package running cat does not count)
    pids_seen: set = field(default_factory=set)
    pids_exited: set = field(default_factory=set)

    @property
    def descendants_still_running(self) -> list[int]:
        return sorted(p for p in self.pids_seen if p is not None and p != self.init_pid
                      and p not in self.pids_exited)

    def completeness_problems(self) -> list[str]:
        """Reasons this trace cannot be treated as complete evidence (empty list = complete)."""
        out = []
        if self.lines == 0:
            out.append("trace is empty")
        if self.parse_warnings:
            out.append(f"{self.parse_warnings} unparseable record(s)")
        if self.unresumed:
            out.append(f"{self.unresumed} syscall(s) never resumed")
        if self.truncated:
            out.append(f"{self.truncated} record(s) with truncated strings")
        if self.lines and self.final_exec:
            if self.final_exec_pid is None:
                out.append(f"completion marker missing (the sandbox init never ran {self.final_exec}): trace cut short")
            elif self.descendants_still_running:
                out.append(f"{len(self.descendants_still_running)} traced process(es) never exited")
        elif self.lines and not self.root_exited:
            out.append("no exit notice for the traced process (trace cut short)")
        return out


def _unescape(s: str) -> str:
    try:
        return s.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except Exception:
        return s


def _strs(text: str) -> list[str]:
    return [_unescape(m) for m in STR_RE.findall(text)]


def _join(base: str | None, path: str) -> str:
    return f"{base.rstrip('/')}/{path}" if base else f"?/{path}"


def _abs(path: str, args: str, cwd: str | None, which: int = 0) -> str:
    """Resolve a path. `which` selects the dirfd annotation that belongs to it (0 = first, 1 = second).
    Unresolvable relative paths get a '?/' prefix so they never look allowed."""
    if path.startswith("/"):
        return path
    notes = FD_ANNOT_RE.findall(args)
    base = notes[which] if len(notes) > which else (notes[0] if notes and which == 0 else cwd)
    return _join(base, path)


def _flags(args: str) -> list[str]:
    return re.findall(r"\bO_[A-Z_]+", args)


def _destination(args: str):
    """(family, addr, port) of an explicit socket address found in the arguments, or None."""
    fam = re.search(r"sa_family=(AF_\w+)", args)
    if not fam:
        return None
    family = fam.group(1)
    port = re.search(r"htons\((\d+)\)", args)
    addr = None
    a4 = re.search(r'inet_addr\("([^"]*)"\)', args)
    a6 = re.search(r'inet_pton\(AF_INET6, "([^"]*)"', args)
    if a4:
        addr = a4.group(1)
    elif a6:
        addr = a6.group(1)
    elif family == "AF_UNIX":
        m = re.search(r'sun_path="([^"]*)"', args)
        addr = m.group(1) if m else None
    return family, addr, int(port.group(1)) if port else None


def _event(ts, pid, name, args, ret, raw, cwd):
    base = dict(ts=ts, pid=pid, syscall=name, args=args, ret=ret, raw=raw)
    strs = _strs(args)
    if name in OPEN_CALLS:
        if not strs:
            return None
        flags = ["O_WRONLY", "O_CREAT", "O_TRUNC"] if name == "creat" else _flags(args)
        kind = "FILE_WRITE" if any(f in WRITE_FLAGS for f in flags) else "FILE_OPEN"
        return Event(kind=kind, path=_abs(strs[0], args, cwd), flags=flags, **base)
    if name == "execve":
        if not strs:
            return None
        return Event(kind="PROC_EXEC", path=_abs(strs[0], "", cwd), argv=strs[1:], **base)
    if name == "execveat":
        notes = FD_ANNOT_RE.findall(args)
        if strs and strs[0]:
            return Event(kind="PROC_EXEC", path=_abs(strs[0], args, cwd), argv=strs[1:], **base)
        # AT_EMPTY_PATH: executing a file descriptor (typically a memfd): the path lives in the fd annotation
        return Event(kind="PROC_EXEC", path=notes[0] if notes else "fd:unknown", argv=strs[1:], **base)
    if name in CONNECT_CALLS or name in SEND_CALLS:
        dest = _destination(args)
        if dest is None:
            return None  # send on a connected socket: the connect() was already recorded
        family, addr, port = dest
        return Event(kind="NET_CONNECT", family=family, addr=addr, port=port, **base)
    if name in RENAME_LIKE:
        if len(strs) < 2:
            return None
        return Event(kind="FILE_WRITE", path=_abs(strs[1], args, cwd, which=1), argv=strs, **base)
    if name in SYMLINK_CALLS:
        if len(strs) < 2:
            return None
        return Event(kind="FILE_WRITE", path=_abs(strs[-1], args, cwd, which=0), argv=strs, **base)
    if name in PATH_MUTATORS:
        if not strs:
            return None
        return Event(kind="FILE_WRITE", path=_abs(strs[0], args if name.endswith(("at", "at2")) else "", cwd), **base)
    if name in EVASION_CALLS:
        return Event(kind="SYSCALL_EVASION", path=strs[0] if strs else None, **base)
    if name in SIGNAL_CALLS:
        m = re.match(r"\s*(-?\d+)", args)
        if m and int(m.group(1)) in SIGNAL_TARGETS:
            return Event(kind="SYSCALL_EVASION", path=f"signal to pid {m.group(1)}", **base)
        return None  # an ordinary signal between the package's own processes
    return None


def _spawn_map(text: str) -> dict:
    """child pid -> parent pid, from clone/fork/vfork return values."""
    children = {}
    for raw in text.splitlines():
        m = SPAWN_RE.match(raw)
        if m:
            children[int(m.group(2))] = int(m.group(1)) if m.group(1) else ROOT_PID
    return children


def parse_trace(text: str, final_exec: str | None = None, init_pid: int = 1) -> ParseResult:
    """`final_exec`: basename of the program the sandbox init (`init_pid`) runs when the package command has finished
    (marker mode). Without it, completeness means 'the first traced process exited'."""
    res = ParseResult(final_exec=final_exec, init_pid=init_pid)
    parent_of = _spawn_map(text)
    cwds: dict = {}
    pending: dict = {}

    def cwd_of(pid, depth=0):
        if pid in cwds:
            return cwds[pid]
        # a process starts in its parent's cwd (any chdir happens later, in the child)
        par = parent_of.get(pid)
        cwds[pid] = cwd_of(par, depth + 1) if par is not None and par != pid and depth < 50 else INITIAL_CWD
        return cwds[pid]

    for raw in text.splitlines():
        if not raw.strip():
            continue
        res.lines += 1
        try:
            m = LINE_RE.match(raw)
            if not m:
                res.parse_warnings += 1
                continue
            pid = int(m.group(1)) if m.group(1) else None
            ts = float(m.group(2))
            body = m.group(3)
            res.pids_seen.add(pid)
            if res.lines == 1:
                res.root_pid = pid
            if body.startswith("+++"):
                if "exited with" in body or "killed by" in body:
                    res.pids_exited.add(pid)
                continue
            if body.startswith("---"):
                continue  # signal notices
            if TRUNCATED_RE.search(body):
                res.truncated += 1
            r = RESUMED_RE.match(body)
            if r:
                prev = pending.pop(pid, None)
                if not prev:
                    res.parse_warnings += 1
                    continue
                ts, prefix = prev
                body = f"{r.group(1)}(" + prefix + r.group(2)
            elif body.endswith(UNFINISHED_SUFFIX):
                head = body[: -len(UNFINISHED_SUFFIX)]
                pending[pid] = (ts, head.split("(", 1)[1] if "(" in head else "")
                continue
            c = CALL_RE.match(body)
            if not c:
                res.parse_warnings += 1
                continue
            name, args, ret = c.group(1), c.group(2), c.group(3) + c.group(4)
            if name in CWD_CALLS:
                if c.group(3) == "0":
                    if name == "chdir":
                        s = _strs(args)
                        if s:
                            cwds[pid] = s[0] if s[0].startswith("/") else f"{cwd_of(pid).rstrip('/')}/{s[0]}"
                    else:  # fchdir(3</some/dir>): the fd annotation names the directory
                        notes = FD_ANNOT_RE.findall(args)
                        if notes:
                            cwds[pid] = notes[0]
                continue
            if name in SPAWN_CALLS:
                continue
            ev = _event(ts, pid, name, args, ret, raw, cwd_of(pid))
            if ev is not None:
                res.events.append(ev)
                if (final_exec and pid == init_pid and ev.kind == "PROC_EXEC" and c.group(3) == "0" and ev.path
                        and ev.path.rsplit("/", 1)[-1] == final_exec):
                    res.final_exec_pid = pid
        except Exception:
            res.parse_warnings += 1
    res.unresumed = len(pending)
    res.root_exited = res.root_pid in res.pids_exited if res.lines else False
    return res
