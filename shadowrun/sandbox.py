"""Container runner implementing blueprint section 4.3. No package code ever runs on the host."""
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import docker

from . import config

# chdir/clone/fork/vfork are added to the blueprint's list so relative paths can be resolved per process.
STRACE_SYSCALLS = "openat,open,connect,execve,rename,unlink,mkdir,symlink,chmod,chdir,clone,clone3,fork,vfork"


@dataclass
class ContainerResult:
    exit_code: int | None
    logs: str
    container_ip: str | None
    timed_out: bool
    t_start: float
    t_end: float
    phases: dict = field(default_factory=dict)


def client() -> docker.DockerClient:
    return docker.from_env()


def seccomp_enabled() -> bool:
    try:
        return bool(json.loads(config.DOCTOR_STATE.read_text()).get("seccomp_bpf", False))
    except Exception:
        return False


def strace_prefix(out="/out/trace.log", seccomp: bool | None = None) -> str:
    use = seccomp_enabled() if seccomp is None else seccomp
    flag = "--seccomp-bpf " if use else ""
    return f"strace -f {flag}-ttt -yy -s 200 -e trace={STRACE_SYSCALLS} -o {out} "


def install_command(name: str, version: str, sha256: str, seccomp: bool | None = None, trace: bool = True) -> str:
    """Offline hash-pinned install, under strace unless trace=False (section 4.2). req.txt is written first."""
    req = f"{name}=={version} --hash=sha256:{sha256}"
    pip = ("pip install --no-index --no-build-isolation --disable-pip-version-check --no-cache-dir -q "
           "--find-links /cache --no-deps --require-hashes -r /work/req.txt --target /work/site")
    prefix = strace_prefix(seccomp=seccomp) if trace else ""
    return f"printf '%s\\n' '{req}' > /work/req.txt && {prefix}{pip}"


def run_container(cmd: str, *, analysis: bool, home: Path | None = None, out_dir: Path | None = None,
                  cache_dir: Path | None = None, timeout: int = config.TIMEOUT_S,
                  network: str = config.NETWORK, env: dict | None = None,
                  image: str = config.SANDBOX_IMAGE) -> ContainerResult:
    """Run `sh -c cmd` in a hardened container. Always removes the container."""
    c = client()
    volumes = {}
    if home is not None:
        volumes[str(home)] = {"bind": "/home/sandbox", "mode": "rw"}
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        volumes[str(out_dir)] = {"bind": "/out", "mode": "rw"}
    if cache_dir is not None:
        volumes[str(cache_dir)] = {"bind": "/cache", "mode": "ro"}
    environment = {"HOME": "/home/sandbox", "USER": "developer",
                   "GIT_AUTHOR_EMAIL": "test@example.invalid", "GIT_AUTHOR_NAME": "Test User"}
    environment.update(env or {})
    t0 = time.time()
    container = None
    timed_out = False
    exit_code = None
    logs = ""
    ip = None
    try:
        container = c.containers.run(
            image, ["sh", "-c", cmd], detach=True, network=network,
            user=f"{config.UID}:{config.GID}", read_only=True,
            tmpfs={p: f"rw,exec,nosuid,size=128m,uid={config.UID},gid={config.GID},mode=1777"
                   for p in ("/tmp", "/work")},
            cap_drop=["ALL"], cap_add=["SYS_PTRACE"] if analysis else None,
            security_opt=["no-new-privileges:true"],
            mem_limit="512m", nano_cpus=1_000_000_000, pids_limit=128,
            volumes=volumes, environment=environment, working_dir="/work",
        )
        container.reload()
        nets = container.attrs["NetworkSettings"]["Networks"]
        ip = (nets.get(network) or {}).get("IPAddress")
        try:
            res = container.wait(timeout=timeout)
            exit_code = res.get("StatusCode")
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
