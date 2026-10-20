"""`shadowrun doctor`: self-test of the sandbox. Any FAIL aborts runs (fail closed)."""
import json
import os
import secrets
import time
import urllib.request

import docker

from . import canary, config, sandbox


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


def _strace_probe(seccomp: bool):
    cs = canary.create_home("doctor-strace")
    try:
        inner = ("python3 -c \"import urllib.request as u\n"
                 "open('/home/sandbox/.ssh/id_rsa').read()\n"
                 f"try: u.urlopen('http://{config.SINK_NAME}:{config.SINK_PORT}/probe',data=b'x',timeout=5)\n"
                 "except Exception: pass\"")
        r, ev = sandbox.run_analysis(inner, home=cs.home, timeout=30, seccomp=seccomp)
        log = ev.trace_text
        ok = (ev.trusted and "id_rsa" in log and "connect(" in log and f"htons({config.SINK_PORT})" in log)
        return ok, r, ev
    finally:
        canary.cleanup_home(cs)


def check_strace():
    ok, r, ev = _strace_probe(seccomp=True)
    seccomp = ok
    if not ok:
        ok, r, ev = _strace_probe(seccomp=False)
    config.DOCTOR_STATE.write_text(json.dumps({"seccomp_bpf": seccomp}))
    if ok:
        return True, f"strace logged canary openat + connect to sink:9000 (--seccomp-bpf={'on' if seccomp else 'off'})"
    return False, f"strace probe failed: {'; '.join(ev.errors + ev.tampered) or r.logs.strip()[-300:]}"


TAMPER_ATTEMPTS = ["echo x >> /trace/trace.log", ": > /trace/trace.log", "rm /trace/trace.log",
                   "mv /trace/trace.log /tmp/stolen", "ls /trace", "cp /dev/null /trace/trace.log",
                   "ln -s /etc/passwd /trace/trace.log", "kill -9 1"]


def check_evidence_isolation():
    """The package user must be unable to modify, delete, replace or list the trace, or kill the tracer."""
    cs = canary.create_home("doctor-tamper")
    try:
        # attempts are referred to by index: their text contains shell redirections that must not reach `echo`
        loop = "; ".join(f"if sh -c '{a}' >/dev/null 2>&1; then echo SUCCEEDED:{i}; else echo BLOCKED:{i}; fi"
                         for i, a in enumerate(TAMPER_ATTEMPTS))
        r, ev = sandbox.run_analysis(loop, home=cs.home, timeout=30)
        succeeded = [TAMPER_ATTEMPTS[int(ln.split(":")[1])] for ln in r.logs.splitlines() if ln.startswith("SUCCEEDED:")]
        blocked = [ln for ln in r.logs.splitlines() if ln.startswith("BLOCKED:")]
        ok = (not succeeded and len(blocked) == len(TAMPER_ATTEMPTS) and ev.trusted and bool(ev.trace_text)
              and ev.strace_rc == 0)
        if ok:
            return True, f"{len(blocked)} tampering attempts blocked; trace intact, root-owned, hash verified"
        return False, (f"succeeded={succeeded} blocked={len(blocked)}/{len(TAMPER_ATTEMPTS)} "
                       f"errors={ev.errors + ev.tampered} rc={ev.strace_rc}")
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
    ("strace records canary openat + connect", check_strace),
    ("rootfs read-only, /tmp executable", check_fs),
    ("pypiserver up, sink dir writable", check_host_services),
    ("package cannot tamper with trace evidence", check_evidence_isolation),
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
