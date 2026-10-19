"""Rule engine over parsed strace events and sink events (blueprint section 6.2).
Detection is on attempts, regardless of syscall return value."""
import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from . import config
from .models import Event, Finding, SEVERITY_ORDER

LOOPBACK_V4 = re.compile(r"^127\.")
RESOLVER = "127.0.0.11"
PERSISTENCE_RE = re.compile(
    r"(/\.bashrc$|/\.bash_profile$|/\.bash_login$|/\.profile$|/\.zshrc$|/\.zprofile$|"
    r"/authorized_keys2?$|/\.config/autostart/|/etc/cron|/var/spool/cron|/crontab$|/etc/profile|/etc/rc\.local$)")


@dataclass
class DetectorConfig:
    allowed_write_prefixes: list[str] = field(default_factory=lambda: ["/work/", "/tmp/", "/home/sandbox/.cache/"])
    allowed_exec: list[str] = field(default_factory=lambda: ["python", "python3", "pip", "pip3", "git"])
    pip_known_execs: list[str] = field(default_factory=list)
    pip_known_write_regex: list[str] = field(default_factory=list)

    @classmethod
    def from_policy(cls, path: Path | None = None) -> "DetectorConfig":
        data = yaml.safe_load((path or config.ROOT / "policies" / "default.yaml").read_text())
        base = data.get("pip_baseline", {})
        return cls(
            allowed_write_prefixes=data["allowed_write_prefixes"],
            allowed_exec=data["allowed_exec"],
            pip_known_execs=base.get("known_execs", []),
            pip_known_write_regex=base.get("known_write_regex", []),
        )


@dataclass
class RunContext:
    canary_paths: list[str]  # absolute paths inside the sandbox
    run_token: str | None = None
    sink_events: list[dict] = field(default_factory=list)
    hash_mismatch: bool = False
    install_failed: bool = False
    timed_out: bool = False


def _norm_exec(path: str) -> str:
    name = PurePosixPath(path).name
    return re.sub(r"^(python3?)\.\d+$", r"\1", name)


def _norm_path(p: str) -> str:
    # strace logs the path as the program passed it, so resolve '..' and '//' (symlinks are not resolved)
    return posixpath.normpath(p)


def _is_loopback(addr: str | None) -> bool:
    return bool(addr) and (LOOPBACK_V4.match(addr) is not None or addr in ("::1", "0.0.0.0", "::"))


def _add(findings: list[Finding], seen: set, rule: str, sev: str, msg: str, **evidence):
    key = (rule, json.dumps(evidence, sort_keys=True, default=str))
    if key in seen:
        return
    seen.add(key)
    findings.append(Finding(rule_id=rule, severity=sev, message=msg, evidence=evidence))


def analyze(events: list[Event], ctx: RunContext, cfg: DetectorConfig | None = None) -> list[Finding]:
    cfg = cfg or DetectorConfig.from_policy()
    findings: list[Finding] = []
    seen: set = set()
    canaries = {_norm_path(p) for p in ctx.canary_paths}
    known_write = [re.compile(r) for r in cfg.pip_known_write_regex]
    allowed_exec = {_norm_exec(x) for x in cfg.allowed_exec} | {_norm_exec(x) for x in cfg.pip_known_execs}

    if ctx.run_token:
        needle = f"CANARY-{ctx.run_token}-"
        for ev in ctx.sink_events:
            hay = json.dumps(ev, default=str)
            if needle in hay:
                toks = sorted(set(re.findall(rf"{re.escape(needle)}\w+", hay)))
                _add(findings, seen, "CANARY_EXFIL", "critical",
                     f"Canary secret reached the sink ({', '.join(toks)})",
                     tokens=toks, method=ev.get("method"), path=ev.get("path"))
    if ctx.hash_mismatch:
        _add(findings, seen, "HASH_MISMATCH", "critical", "pip rejected the file: SHA-256 does not match the pin")

    for ev in events:
        if ev.kind in ("FILE_OPEN", "FILE_WRITE") and ev.path:
            p = _norm_path(ev.path)
            if p in canaries:
                _add(findings, seen, "CANARY_READ", "high", f"Package code opened canary file {p}",
                     path=p, syscall=ev.syscall, pid=ev.pid)
        if ev.kind == "FILE_WRITE" and ev.path:
            p = _norm_path(ev.path)
            if PERSISTENCE_RE.search(p):
                _add(findings, seen, "PERSISTENCE_WRITE", "high", f"Write to persistence location {p}",
                     path=p, syscall=ev.syscall, pid=ev.pid)
            elif (not any(p.startswith(pre) or p + "/" == pre for pre in cfg.allowed_write_prefixes)
                  and not any(r.search(p) for r in known_write)):
                _add(findings, seen, "WRITE_OUTSIDE_ALLOWED", "medium", f"Write outside allowed paths: {p}",
                     path=p, syscall=ev.syscall, pid=ev.pid)
        elif ev.kind == "NET_CONNECT" and ev.family in ("AF_INET", "AF_INET6"):
            if not _is_loopback(ev.addr) and ev.addr != RESOLVER:
                _add(findings, seen, "NET_OUTBOUND", "high",
                     f"Outbound connect to {ev.addr}:{ev.port} during an offline install",
                     addr=ev.addr, port=ev.port, pid=ev.pid)
        elif ev.kind == "PROC_EXEC" and ev.path:
            if _norm_exec(ev.path) not in allowed_exec:
                _add(findings, seen, "UNEXPECTED_EXEC", "medium", f"Unexpected exec of {ev.path}",
                     path=ev.path, argv=ev.argv[:6], pid=ev.pid)

    if ctx.timed_out:
        _add(findings, seen, "SANDBOX_TIMEOUT", "medium", "Run exceeded the timeout")
    if ctx.install_failed and not ctx.hash_mismatch:
        _add(findings, seen, "INSTALL_FAILED", "low", "pip failed for a reason other than a hash mismatch")
    return findings


def max_severity(findings: list[Finding]) -> str:
    return max((f.severity for f in findings), key=SEVERITY_ORDER.get, default="info")
