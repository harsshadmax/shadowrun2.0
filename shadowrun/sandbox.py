"""Container runners implementing blueprint section 4.3. No package code ever runs on the host.

Evidence isolation (security fix): in the analysis container the tracer and the package live in different
privilege domains.

  * strace runs as root (capabilities: SYS_PTRACE, SETUID, SETGID only) and writes the trace to /trace, a
    root-only tmpfs (mode 0700) that exists only inside the container.
  * the package runs as the unprivileged host uid, started with `setpriv` under strace. It cannot open, truncate,
    delete, replace or list anything in /trace, and it cannot signal or ptrace the tracer.
  * the host fetches the trace with `docker exec` as root, which is a separate channel the package cannot write to,
    and verifies ownership, mode, size and SHA-256 before the detector sees a single line.
"""
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import docker

from . import config

# chdir/clone/fork/vfork are added to the blueprint's list so relative paths can be resolved per process.
STRACE_SYSCALLS = "openat,open,connect,execve,rename,unlink,mkdir,symlink,chmod,chdir,clone,clone3,fork,vfork"
STRACE_STRSIZE = 4096  # long enough that no realistic path is cut off; truncation is still detected downstream
TRACE_DIR_IN_BOX = "/trace"
MAX_TRACE_BYTES = 32 * 1024 * 1024
EXPECTED_STAT = (0, 0, "600", "regular file")  # uid, gid, mode, type of /trace/trace.log


@dataclass
class ContainerResult:
    exit_code: int | None
    logs: str
    container_ip: str | None
    timed_out: bool
    t_start: float
    t_end: float
    phases: dict = field(default_factory=dict)


@dataclass
class Evidence:
    """Everything the host learned about the trace, and whether it can be trusted."""
    trace_text: str = ""
    strace_rc: int | None = None
    sha256: str | None = None
    size: int | None = None
    done: bool = False  # the in-container wrapper reached its end marker
    errors: list[str] = field(default_factory=list)  # collection problems: evidence unavailable or incomplete
    tampered: list[str] = field(default_factory=list)  # integrity violations: ownership, mode, hash mismatch

    @property
    def trusted(self) -> bool:
        return not self.errors and not self.tampered


def client() -> docker.DockerClient:
    return docker.from_env()


def seccomp_enabled() -> bool:
    try:
        return bool(json.loads(config.DOCTOR_STATE.read_text()).get("seccomp_bpf", False))
    except Exception:
        return False


def strace_prefix(out: str = f"{TRACE_DIR_IN_BOX}/trace.log", seccomp: bool | None = None) -> str:
    use = seccomp_enabled() if seccomp is None else seccomp
    flag = "--seccomp-bpf " if use else ""
    return f"strace -f {flag}-ttt -yy -s {STRACE_STRSIZE} -e trace={STRACE_SYSCALLS} -o {out} "


def install_command(name: str, version: str, sha256: str) -> str:
    """Package-side command: offline hash-pinned install (section 4.2). req.txt is written first."""
    req = f"{name}=={version} --hash=sha256:{sha256}"
    pip = ("pip install --no-index --no-build-isolation --disable-pip-version-check --no-cache-dir -q "
           "--find-links /cache --no-deps --require-hashes -r /work/req.txt --target /work/site")
    return f"printf '%s\\n' '{req}' > /work/req.txt && {pip}"


def _env(extra: dict | None = None) -> dict:
    environment = {"HOME": "/home/sandbox", "USER": "developer",
                   "GIT_AUTHOR_EMAIL": "test@example.invalid", "GIT_AUTHOR_NAME": "Test User"}
    environment.update(extra or {})
    return environment


def _tmpfs(extra: dict | None = None) -> dict:
    t = {p: f"rw,exec,nosuid,size=128m,uid={config.UID},gid={config.GID},mode=1777" for p in ("/tmp", "/work")}
    t.update(extra or {})
    return t


def _volumes(home: Path | None, cache_dir: Path | None) -> dict:
    v = {}
    if home is not None:
        v[str(home)] = {"bind": "/home/sandbox", "mode": "rw"}
    if cache_dir is not None:
        v[str(cache_dir)] = {"bind": "/cache", "mode": "ro"}
    return v


def run_container(cmd: str, *, home: Path | None = None, cache_dir: Path | None = None,
                  timeout: int = config.TIMEOUT_S, network: str = config.NETWORK, env: dict | None = None,
                  image: str = config.SANDBOX_IMAGE) -> ContainerResult:
    """Run `sh -c cmd` as the unprivileged host uid with NO capabilities and no tracing. Used for the exposed
    baseline container and for doctor probes. Always removes the container."""
    c = client()
    t0 = time.time()
    container = None
    timed_out = False
    exit_code = None
    logs = ""
    ip = None
    try:
        container = c.containers.run(
            image, ["sh", "-c", cmd], detach=True, network=network,
            user=f"{config.UID}:{config.GID}", read_only=True, tmpfs=_tmpfs(),
            cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
            mem_limit="512m", nano_cpus=1_000_000_000, pids_limit=128,
            volumes=_volumes(home, cache_dir), environment=_env(env), working_dir="/work",
        )
        container.reload()
        ip = (container.attrs["NetworkSettings"]["Networks"].get(network) or {}).get("IPAddress")
        try:
            exit_code = container.wait(timeout=timeout).get("StatusCode")
        except Exception:
            timed_out = True
            try:
                container.kill()
            except Exception:
                pass
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
    return ContainerResult(exit_code, logs, ip, timed_out, t0, time.time())


def _wrapper_script(seccomp: bool) -> str:
    """Runs as root inside the analysis container. The package command runs under setpriv as the host uid."""
    trace = strace_prefix(seccomp=seccomp)
    return (
        "umask 077; "
        f"{trace}setpriv --reuid={config.UID} --regid={config.GID} --clear-groups -- sh -c \"$PACKAGE_CMD\"; "
        f"echo $? > {TRACE_DIR_IN_BOX}/rc; touch {TRACE_DIR_IN_BOX}/done; "
        "exec sleep 3600"
    )


def _exec(container, cmd: list[str], timeout_s: float = 10) -> tuple[int, bytes]:
    res = container.exec_run(cmd, user="0:0", demux=False)
    return res.exit_code, res.output or b""


def collect_evidence(container, timed_out: bool) -> Evidence:
    """Fetch and verify the trace over `docker exec` (a channel the package cannot touch)."""
    ev = Evidence()
    try:
        container.reload()
        if container.status != "running":
            ev.errors.append(f"container not running when collecting evidence ({container.status})")
            return ev
        rc_code, _ = _exec(container, ["test", "-f", f"{TRACE_DIR_IN_BOX}/done"])
        ev.done = rc_code == 0
        if not ev.done and not timed_out:
            ev.errors.append("tracer wrapper did not finish")
        code, out = _exec(container, ["sh", "-c",
                                      f"stat -c '%u %g %a %F' {TRACE_DIR_IN_BOX}/trace.log && "
                                      f"wc -c < {TRACE_DIR_IN_BOX}/trace.log && "
                                      f"sha256sum {TRACE_DIR_IN_BOX}/trace.log && "
                                      f"cat {TRACE_DIR_IN_BOX}/rc 2>/dev/null || true"])
        lines = out.decode("utf-8", "replace").splitlines()
        if code != 0 or len(lines) < 3:
            ev.errors.append("trace file missing or unreadable")
            return ev
        uid, gid, mode, ftype = lines[0].split(" ", 3)
        if (int(uid), int(gid), mode, ftype) != EXPECTED_STAT:
            ev.tampered.append(f"trace file ownership/mode/type changed: {lines[0]!r}")
        ev.size = int(lines[1].strip())
        in_box_sha = lines[2].split()[0]
        if len(lines) > 3 and lines[3].strip().lstrip("-").isdigit():
            ev.strace_rc = int(lines[3].strip())
        if ev.size > MAX_TRACE_BYTES:
            ev.errors.append(f"trace larger than {MAX_TRACE_BYTES} bytes; not collected")
            return ev
        code, blob = _exec(container, ["cat", f"{TRACE_DIR_IN_BOX}/trace.log"])
        if code != 0:
            ev.errors.append("trace could not be read")
            return ev
        ev.sha256 = hashlib.sha256(blob).hexdigest()
        if len(blob) != ev.size or ev.sha256 != in_box_sha:
            ev.tampered.append("trace changed or was corrupted between in-container hash and transfer")
        ev.trace_text = blob.decode("utf-8", "replace")
    except Exception as e:  # any failure to collect is itself a finding, never an implicit pass
        ev.errors.append(f"evidence collection failed: {type(e).__name__}: {e}")
    return ev


def run_analysis(inner_cmd: str, *, home: Path, cache_dir: Path | None = None, timeout: int = config.TIMEOUT_S,
                 seccomp: bool | None = None, network: str = config.NETWORK) -> tuple[ContainerResult, Evidence]:
    """Run `inner_cmd` (package side) under strace with the evidence isolated from the package."""
    use_seccomp = seccomp_enabled() if seccomp is None else seccomp
    c = client()
    t0 = time.time()
    container = None
    timed_out = False
    ip = None
    logs = ""
    ev = Evidence(errors=["container did not start"])
    try:
        container = c.containers.run(
            config.SANDBOX_IMAGE, ["sh", "-c", _wrapper_script(use_seccomp)], detach=True, network=network,
            user="0:0", read_only=True,
            tmpfs=_tmpfs({TRACE_DIR_IN_BOX: "rw,nosuid,nodev,noexec,size=64m,uid=0,gid=0,mode=0700"}),
            cap_drop=["ALL"], cap_add=["SYS_PTRACE", "SETUID", "SETGID"],
            security_opt=["no-new-privileges:true"],
            mem_limit="512m", nano_cpus=1_000_000_000, pids_limit=128,
            volumes=_volumes(home, cache_dir), environment=_env({"PACKAGE_CMD": inner_cmd}), working_dir="/work",
        )
        container.reload()
        ip = (container.attrs["NetworkSettings"]["Networks"].get(network) or {}).get("IPAddress")
        deadline = time.time() + timeout
        while True:
            container.reload()
            if container.status != "running":
                break
            if _exec(container, ["test", "-f", f"{TRACE_DIR_IN_BOX}/done"])[0] == 0:
                break
            if time.time() > deadline:
                timed_out = True
                break
            time.sleep(0.15)
        ev = collect_evidence(container, timed_out)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
    except Exception as e:
        ev.errors.append(f"sandbox failure: {type(e).__name__}: {e}")
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
    res = ContainerResult(ev.strace_rc, logs, ip, timed_out, t0, time.time())
    return res, ev
