"""`shadowrun doctor`: self-test of the sandbox. Any FAIL aborts runs (fail closed)."""
import os
import secrets
import time
import urllib.request

from . import canary, config, detector, monitor, sandbox


def _py(code: str) -> str:
    return f"python3 -c \"{code}\""


def check_docker():
    try:
        c = sandbox.client()
        c.ping()
        for img in (config.SANDBOX_IMAGE, config.SINK_IMAGE):
            c.images.get(img)
        return True, "docker reachable; images present"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def check_network():
    try:
        n = sandbox.client().networks.get(config.NETWORK)
        internal = bool(n.attrs.get("Internal"))
        return internal, f"{config.NETWORK} Internal={internal}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def check_no_internet():
    code = ("import socket,sys\n"
            "for h in ('1.1.1.1','example.com'):\n"
            "  try:\n"
            "    s=socket.create_connection((h,443),timeout=4); print('REACHED',h); sys.exit(1)\n"
            "  except OSError as e: print('blocked',h,e)\n")
    r = sandbox.run_container(f"python3 - <<'EOF'\n{code}EOF", timeout=30)
    return r.exit_code == 0 and "REACHED" not in r.logs, r.logs.strip().replace("\n", " | ")


def check_sink():
    marker = "DOCTOR-" + secrets.token_hex(4)
    code = (f"import urllib.request as u; "
            f"print(u.urlopen(u.Request('http://{config.SINK_NAME}:{config.SINK_PORT}/doctor',"
            f"data=b'{marker}',method='POST'),timeout=5).status)")
    ok = False
    r = None
    for _ in range(5):
        r = sandbox.run_container(_py(code), timeout=20)
        if r.exit_code == 0:
            ok = True
            break
        time.sleep(1)
    if not ok:
        return False, f"sandbox could not reach sink: {r.logs.strip()[-200:]}"
    time.sleep(0.5)
    seen = config.SINK_LOG.exists() and marker in config.SINK_LOG.read_text()
    return seen, "sandbox reached sink:9000 and sink logged the POST" if seen else "sink did not log the POST"


def check_strace():
    """The tracer sidecar must attach, record a canary open and a connect, and deliver a complete, trusted trace."""
    cs = canary.create_home("doctor-strace")
    try:
        inner = ("python3 -c \"import urllib.request as u\n"
                 "open('/home/sandbox/.ssh/id_rsa').read()\n"
                 f"try: u.urlopen('http://{config.SINK_NAME}:{config.SINK_PORT}/probe',data=b'x',timeout=5)\n"
                 "except Exception: pass\"")
        r, ev = sandbox.run_analysis(inner, home=cs.home, timeout=30)
        pr = monitor.parse_trace(ev.trace_text, final_exec=sandbox.FINAL_EXEC)
        problems = pr.completeness_problems()
        log = ev.trace_text
        ok = (ev.trusted and not problems and "id_rsa" in log and "connect(" in log
              and f"htons({config.SINK_PORT})" in log)
        if ok:
            return True, "tracer sidecar attached; canary openat + connect to sink:9000 recorded; trace complete and trusted"
        return False, f"strace probe failed: {'; '.join(ev.errors + ev.tampered + problems) or r.logs.strip()[-300:]}"
    finally:
        canary.cleanup_home(cs)


# Run INSIDE the package container: everything an attacker could try against the tracer or its evidence.
ISOLATION_PROBE = r"""
echo "UID:$(id -u)"
grep -E '^(CapEff|CapBnd|NoNewPrivs):' /proc/self/status | tr -d ' \t' | sed 's/^/STATUS:/'
[ -e /trace ] && echo "SUCCEEDED:trace-dir-visible" || echo "BLOCKED:trace-dir-not-visible"
n=0
for d in /proc/[0-9]*; do
  p=${d#/proc/}; [ "$p" = 1 ] && continue
  u=$(awk '/^Uid:/{print $2}' $d/status 2>/dev/null); [ "$u" = 0 ] || continue
  n=$((n+1))
  kill -9 $p 2>/dev/null && echo "SUCCEEDED:kill-root-$p" || echo "BLOCKED:kill-root"
  cat $d/environ >/dev/null 2>&1 && echo "SUCCEEDED:read-environ-$p" || echo "BLOCKED:read-environ"
  ls $d/fd >/dev/null 2>&1 && echo "SUCCEEDED:list-fds-$p" || echo "BLOCKED:list-fds"
  (echo x > $d/mem) 2>/dev/null && echo "SUCCEEDED:write-mem-$p" || echo "BLOCKED:write-mem"
done
echo "ROOTPROCS:$n"
"""


def check_evidence_isolation():
    """The package container has no root and no capabilities, cannot see the trace, and cannot touch the tracer."""
    cs = canary.create_home("doctor-isolation")
    try:
        r, ev = sandbox.run_analysis(ISOLATION_PROBE, home=cs.home, timeout=40)
        lines = r.logs.splitlines()
        succeeded = [ln for ln in lines if ln.startswith("SUCCEEDED:")]
        blocked = [ln for ln in lines if ln.startswith("BLOCKED:")]
        uid = next((ln.split(":", 1)[1] for ln in lines if ln.startswith("UID:")), None)
        status = {k: v for ln in lines if ln.startswith("STATUS:") for k, v in [ln[7:].split(":", 1)]}
        rootprocs = next((int(ln.split(":", 1)[1]) for ln in lines if ln.startswith("ROOTPROCS:")), 0)
        caps_zero = (status.get("CapEff") == "0" * 16 and status.get("CapBnd") == "0" * 16
                     and status.get("NoNewPrivs") == "1")
        ok = (not succeeded and uid not in (None, "0") and caps_zero and rootprocs >= 1
              and sum(1 for b in blocked if b == "BLOCKED:kill-root") >= 1 and ev.trusted and bool(ev.trace_text))
        if ok:
            return True, (f"package uid {uid}, CapEff=CapBnd=0, no-new-privileges; /trace invisible; "
                          f"{len(blocked)} attacks on {rootprocs} tracer-side root process(es) all denied; trace intact")
        return False, (f"uid={uid} caps={status} rootprocs={rootprocs} succeeded={succeeded} blocked={len(blocked)} "
                       f"errors={ev.errors + ev.tampered}")
    finally:
        canary.cleanup_home(cs)


# Run INSIDE the package container: calls that bypass openat()/connect() unless the tracer is told about them.
COVERAGE_PROBE = r"""python3 - <<'EOF'
import ctypes, socket
libc = ctypes.CDLL(None, use_errno=True)
how = (ctypes.c_uint64 * 3)(0, 0, 0)
fd = libc.syscall(437, -100, b"/home/sandbox/.ssh/id_rsa", ctypes.byref(how), 24)       # openat2 of a canary
if fd >= 0:
    libc.close(fd)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", (socket.gethostbyname("sink"), 9000))                                  # sendto, no connect()
except OSError:
    pass
libc.close(libc.syscall(85, b"/home/sandbox/.profile", 0o644))                            # creat
libc.syscall(265, -100, b"/home/sandbox/.profile", -100, b"/home/sandbox/.bashrc", 0)     # linkat onto .bashrc
mfd = libc.syscall(319, b"x", 0)                                                          # memfd_create
libc.syscall(322, mfd, b"", None, None, 0x1000)                                           # execveat(AT_EMPTY_PATH)
libc.syscall(425, 4, ctypes.byref(how))                                                   # io_uring_setup
libc.syscall(165, b"none", b"/mnt", b"tmpfs", 0, 0)                                       # mount
EOF"""
COVERAGE_EXPECT_CALLS = ["openat2", "sendto", "creat", "linkat", "memfd_create", "execveat", "io_uring_setup", "mount"]
COVERAGE_EXPECT_RULES = {"CANARY_READ", "NET_OUTBOUND", "PERSISTENCE_WRITE", "EVASION_SYSCALL"}


def check_syscall_coverage():
    """Self-test of what the tracer collects: calls that bypass openat()/connect() must be recorded AND detected."""
    cs = canary.create_home("doctor-coverage")
    try:
        r, ev = sandbox.run_analysis(COVERAGE_PROBE, home=cs.home, timeout=40)
        pr = monitor.parse_trace(ev.trace_text, final_exec=sandbox.FINAL_EXEC)
        seen = {e.syscall for e in pr.events}
        missing = [c for c in COVERAGE_EXPECT_CALLS if c not in seen]
        ctx = detector.RunContext(canary_paths=list(cs.canary_paths.values()), trace_problems=pr.completeness_problems(),
                                  init_pid=pr.final_exec_pid)
        rules = {f.rule_id for f in detector.analyze(pr.events, ctx)}
        gaps = sorted(COVERAGE_EXPECT_RULES - rules)
        if ev.trusted and not missing and not gaps:
            return True, (f"tracer recorded all {len(COVERAGE_EXPECT_CALLS)} bypass syscalls "
                          f"({', '.join(COVERAGE_EXPECT_CALLS)}) and the detector fired {sorted(COVERAGE_EXPECT_RULES)}")
        return False, f"missing syscalls={missing} undetected rules={gaps} errors={ev.errors + ev.tampered}"
    finally:
        canary.cleanup_home(cs)


def check_fs():
    r = sandbox.run_container("! touch /etc/x 2>/dev/null && cp /bin/true /tmp/t && /tmp/t && echo ok", timeout=20)
    return r.exit_code == 0 and "ok" in r.logs, "rootfs read-only; /tmp executable" if r.exit_code == 0 else r.logs.strip()


def check_host_services():
    try:
        urllib.request.urlopen(config.PYPI_URL + "/", timeout=3)
        pypi = True
    except Exception:
        pypi = False
    config.SINK_DIR.mkdir(parents=True, exist_ok=True)
    writable = os.access(config.SINK_DIR, os.W_OK)
    return pypi and writable, f"pypiserver reachable={pypi}; sink dir writable={writable}"


CHECKS = [
    ("docker reachable, images present", check_docker),
    ("shadowrun_net is internal", check_network),
    ("sandbox cannot reach internet", check_no_internet),
    ("sandbox reaches sink:9000", check_sink),
    ("strace sidecar records canary openat + connect", check_strace),
    ("rootfs read-only, /tmp executable", check_fs),
    ("pypiserver up, sink dir writable", check_host_services),
    ("package has no privileges and cannot reach the tracer", check_evidence_isolation),
    ("tracer collects the syscalls that bypass openat/connect", check_syscall_coverage),
]


def run_checks() -> list[dict]:
    out = []
    for i, (name, fn) in enumerate(CHECKS, 1):
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        out.append({"n": i, "name": name, "ok": bool(ok), "detail": detail})
    return out


def run_doctor(verbose=True) -> bool:
    checks = run_checks()
    all_ok = all(c["ok"] for c in checks)
    if verbose:
        for c in checks:
            print(f"{c['n']}. [{'PASS' if c['ok'] else 'FAIL'}] {c['name']} -- {c['detail']}")
        print("DOCTOR:", "ALL PASS" if all_ok else "FAILED (runs refused)")
    return all_ok
