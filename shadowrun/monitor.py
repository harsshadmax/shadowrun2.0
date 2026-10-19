"""strace log parser. Never raises on odd input; unknown lines are counted in parse_warnings."""
import re
from dataclasses import dataclass, field

from .models import Event

LINE_RE = re.compile(r"^(?:(\d+)\s+)?(\d+\.\d+)\s+(.*)$")
CALL_RE = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(.*)$")
RESUMED_RE = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
UNFINISHED_SUFFIX = " <unfinished ...>"
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
DIRFD_RE = re.compile(r"^\s*(?:AT_FDCWD|\d+)<([^>]*)>")
SPAWN_RE = re.compile(
    r"^(?:(\d+)\s+)?\d+\.\d+\s+(?:(?:clone3?|fork|vfork)\(.*\)|<\.\.\. (?:clone3?|fork|vfork) resumed>.*)\s+=\s+(\d+)\b")
INITIAL_CWD = "/work"
ROOT_PID = None  # key used for logs without pid prefixes (single-process traces)


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    parse_warnings: int = 0


def _unescape(s: str) -> str:
    try:
        return s.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except Exception:
        return s


def _strs(text: str) -> list[str]:
    return [_unescape(m) for m in STR_RE.findall(text)]


def _abs(path: str, args: str, cwd: str | None) -> str:
    """Resolve a path. Unresolvable relative paths get a '?/' prefix so they never look allowed."""
    if path.startswith("/"):
        return path
    m = DIRFD_RE.match(args)
    base = m.group(1) if m else cwd
    return f"{base.rstrip('/')}/{path}" if base else f"?/{path}"


def _flags(args: str) -> list[str]:
    return re.findall(r"\bO_[A-Z_]+", args)


def _event(ts, pid, name, args, ret, raw, cwd):
    base = dict(ts=ts, pid=pid, syscall=name, args=args, ret=ret, raw=raw)
    strs = _strs(args)
    if name in ("openat", "open"):
        if not strs:
            return None
        flags = _flags(args)
        kind = "FILE_WRITE" if any(f in WRITE_FLAGS for f in flags) else "FILE_OPEN"
        return Event(kind=kind, path=_abs(strs[0], args, cwd), flags=flags, **base)
    if name == "execve":
        if not strs:
            return None
        return Event(kind="PROC_EXEC", path=_abs(strs[0], "", cwd), argv=strs[1:], **base)
    if name == "connect":
        fam = re.search(r"sa_family=(AF_\w+)", args)
        family = fam.group(1) if fam else None
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
        return Event(kind="NET_CONNECT", family=family, addr=addr, port=int(port.group(1)) if port else None, **base)
    if name in ("rename", "renameat", "renameat2"):
        if len(strs) < 2:
            return None
        return Event(kind="FILE_WRITE", path=_abs(strs[1], "", cwd), argv=strs, **base)
    if name in ("unlink", "unlinkat", "mkdir", "mkdirat", "chmod", "fchmodat"):
        if not strs:
            return None
        return Event(kind="FILE_WRITE", path=_abs(strs[0], args if name.endswith("at") else "", cwd), **base)
    if name in ("symlink", "symlinkat"):
        if not strs:
            return None
        return Event(kind="FILE_WRITE", path=_abs(strs[-1], "", cwd), argv=strs, **base)
    return None


def _spawn_map(text: str) -> dict:
    """child pid -> parent pid, from clone/fork/vfork return values."""
    children = {}
    for raw in text.splitlines():
        m = SPAWN_RE.match(raw)
        if m:
            children[int(m.group(2))] = int(m.group(1)) if m.group(1) else ROOT_PID
    return children


def parse_trace(text: str) -> ParseResult:
    res = ParseResult()
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
        try:
            m = LINE_RE.match(raw)
            if not m:
                res.parse_warnings += 1
                continue
            pid = int(m.group(1)) if m.group(1) else None
            ts = float(m.group(2))
            body = m.group(3)
            if body.startswith(("+++", "---")):
                continue  # exit / signal notices
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
            if name == "chdir":
                s = _strs(args)
                if s and c.group(3) == "0":
                    cwds[pid] = s[0] if s[0].startswith("/") else f"{cwd_of(pid).rstrip('/')}/{s[0]}"
                continue
            if name in ("clone", "clone3", "fork", "vfork"):
                continue
            ev = _event(ts, pid, name, args, ret, raw, cwd_of(pid))
            if ev is not None:
                res.events.append(ev)
        except Exception:
            res.parse_warnings += 1
    return res
