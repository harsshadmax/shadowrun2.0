"""Container runners implementing blueprint section 4.3. No package code ever runs on the host.

Privilege design of the analysis sandbox (two containers, one shared PID namespace):

  package container   user = the host uid, `cap_drop ALL` (CapEff = CapBnd = 0), no-new-privileges, read-only root,
                      on the internal network. No root process exists in it at all. Its init waits for a `go` file in
                      a read-only mount, runs the install command, prints the exit status, then parks itself in `cat`.
  tracer container    root, `cap_drop ALL` + SYS_PTRACE only, NO network, read-only root, no host mounts. Joined to the
                      package container's PID namespace (`pid_mode=container:<id>`), it runs `strace -f -p 1` and keeps
                      the trace in a root-only tmpfs that the package container cannot see: it is a different mount
                      namespace.

  The package cannot read, write, replace or list the trace, cannot signal or ptrace the tracer (different uid, no
  capabilities), and has no setuid/setgid ability to speak of. The host fetches the trace with `docker exec` into the
  tracer container and verifies owner, mode, size and SHA-256 before the detector sees a line.

Residual risk, stated plainly: the tracer container is root with CAP_SYS_PTRACE and shares a PID namespace with the
package container. A kernel or container-runtime vulnerability reachable through ptrace could turn that into a host
compromise. It has no network, no host mounts and no other capabilities, but it is not a hard boundary. Rootless Docker,
user-namespace remapping or gVisor/Firecracker would shrink the risk and are on the roadmap.
"""
import hashlib
import json
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import docker

from . import config, monitor

STRACE_SYSCALLS = monitor.strace_filter()  # built from the parser's syscall groups so tracer and parser cannot drift
STRACE_STRSIZE = 4096  # long enough that no realistic path is cut off; truncation is still detected downstream
TRACE_DIR_IN_BOX = "/trace"
MAX_TRACE_BYTES = 64 * 1024 * 1024
EXPECTED_STAT = (0, 0, "600", "regular file")  # uid, gid, mode, type of /trace/trace.log (inside the tracer container)
FINAL_EXEC = "cat"  # the package container's init runs this when the install command has finished
RC_RE = re.compile(r"^SHADOWRUN_RC=(\d+)\s*$", re.M)

PACKAGE_INIT = ('until [ -e /ctl/go ]; do :; done; sh -c "$PACKAGE_CMD"; echo "SHADOWRUN_RC=$?"; exec ' + FINAL_EXEC)
TRACER_SCRIPT = (
    "umask 077; "
    f"strace -f -ttt -yy -s {STRACE_STRSIZE} -e trace={STRACE_SYSCALLS} -o {TRACE_DIR_IN_BOX}/trace.log -p 1 & "
    f"SP=$!; echo $SP > {TRACE_DIR_IN_BOX}/strace.pid; wait $SP; "
    f"echo $? > {TRACE_DIR_IN_BOX}/rc; touch {TRACE_DIR_IN_BOX}/done; exec sleep 3600"
)
# exit 0 = the package init reached `cat` and no other non-root process is left; 1 = init not finished; 2 = stragglers
DONE_CHECK = (
    'case "$(readlink /proc/1/exe)" in */' + FINAL_EXEC + ') ;; *) exit 1;; esac; '
    'for d in /proc/[0-9]*; do p=${d#/proc/}; [ "$p" = 1 ] && continue; '
    "u=$(awk '/^Uid:/{print $2}' $d/status 2>/dev/null); [ -n \"$u\" ] && [ \"$u\" != 0 ] && exit 2; done; exit 0"
)


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
    done: bool = False  # the tracer wrapper reached its end marker
    errors: list[str] = field(default_factory=list)  # collection problems: evidence unavailable or incomplete
    tampered: list[str] = field(default_factory=list)  # integrity violations: ownership, mode, hash mismatch

    @property
    def trusted(self) -> bool:
        return not self.errors and not self.tampered


def client() -> docker.DockerClient:
    return docker.from_env()


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


def _volumes(home: Path | None, cache_dir: Path | None, ctl: Path | None = None) -> dict:
    v = {}
    if home is not None:
        v[str(home)] = {"bind": "/home/sandbox", "mode": "rw"}
    if cache_dir is not None:
        v[str(cache_dir)] = {"bind": "/cache", "mode": "ro"}
    if ctl is not None:
        v[str(ctl)] = {"bind": "/ctl", "mode": "ro"}
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


def _exec(container, cmd: list[str]) -> tuple[int, bytes]:
    res = container.exec_run(cmd, user="0:0", demux=False)
    return res.exit_code, res.output or b""


def collect_evidence(container, timed_out: bool) -> Evidence:
    """Fetch and verify the trace over `docker exec` into the tracer container (the package cannot reach it)."""
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


def _wait_attached(tracer, pkg, deadline: float) -> bool:
    """True once the tracer is attached to the package init (TracerPid != 0)."""
    while time.time() < deadline:
        tracer.reload()
        pkg.reload()
        if tracer.status != "running" or pkg.status != "running":
            return False
        code, out = _exec(tracer, ["grep", "-E", r"^TracerPid:\s*[1-9]", "/proc/1/status"])
        if code == 0 and out:
            return True
        time.sleep(0.05)
    return False


def run_analysis(inner_cmd: str, *, home: Path, cache_dir: Path | None = None, timeout: int = config.TIMEOUT_S,
                 network: str = config.NETWORK) -> tuple[ContainerResult, Evidence]:
    """Run `inner_cmd` (package side) under strace, with the tracer in a separate, network-less sidecar container."""
    c = client()
    t0 = time.time()
    pkg = tracer = None
    ctl = config.DATA / "ctl" / uuid.uuid4().hex[:10]
    timed_out = False
    ip = None
    logs = ""
    ev = Evidence(errors=["container did not start"])
    try:
        ctl.mkdir(parents=True, exist_ok=True)
        ctl.chmod(0o755)
        pkg = c.containers.run(
            config.SANDBOX_IMAGE, ["sh", "-c", PACKAGE_INIT], detach=True, network=network,
            user=f"{config.UID}:{config.GID}", read_only=True, tmpfs=_tmpfs(), stdin_open=True,
            cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
            mem_limit="512m", nano_cpus=1_000_000_000, pids_limit=128,
            volumes=_volumes(home, cache_dir, ctl), environment=_env({"PACKAGE_CMD": inner_cmd}), working_dir="/work",
        )
        pkg.reload()
        ip = (pkg.attrs["NetworkSettings"]["Networks"].get(network) or {}).get("IPAddress")
        tracer = c.containers.run(
            config.SANDBOX_IMAGE, ["sh", "-c", TRACER_SCRIPT], detach=True, network_mode="none",
            pid_mode=f"container:{pkg.id}", user="0:0", read_only=True,
            tmpfs={TRACE_DIR_IN_BOX: "rw,nosuid,nodev,noexec,size=96m,uid=0,gid=0,mode=0700"},
            cap_drop=["ALL"], cap_add=["SYS_PTRACE"], security_opt=["no-new-privileges:true"],
            mem_limit="256m", pids_limit=64, working_dir="/",
        )
        deadline = time.time() + timeout
        if not _wait_attached(tracer, pkg, min(deadline, time.time() + 10)):
            ev = Evidence(errors=["tracer could not attach to the package container"])
        else:
            (ctl / "go").write_text("go")  # the package init was waiting for this; it is already being traced
            while True:
                pkg.reload()
                if pkg.status != "running":
                    break
                if _exec(tracer, ["sh", "-c", DONE_CHECK])[0] == 0:
                    break
                if time.time() > deadline:
                    timed_out = True
                    break
                time.sleep(0.15)
            try:  # stop the tracer cleanly so every event is flushed, then wait for its done marker
                tracer.reload()
                if tracer.status == "running":
                    _exec(tracer, ["sh", "-c", f"kill -INT $(cat {TRACE_DIR_IN_BOX}/strace.pid)"])
                    for _ in range(100):
                        if _exec(tracer, ["test", "-f", f"{TRACE_DIR_IN_BOX}/done"])[0] == 0:
                            break
                        time.sleep(0.05)
            except Exception:
                pass
            ev = collect_evidence(tracer, timed_out)
        try:
            logs = pkg.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        except Exception:
            logs = ""
    except Exception as e:
        ev.errors.append(f"sandbox failure: {type(e).__name__}: {e}")
    finally:
        for cont in (tracer, pkg):
            if cont is not None:
                try:
                    cont.remove(force=True)
                except Exception:
                    pass
        shutil.rmtree(ctl, ignore_errors=True)
    rcs = RC_RE.findall(logs)
    pkg_rc = int(rcs[-1]) if rcs else None
    res = ContainerResult(pkg_rc, logs, ip, timed_out, t0, time.time())
    return res, ev
