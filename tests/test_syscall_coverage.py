"""What the tracer collects decides what can be detected. Calls that bypass openat()/connect() must be both
collected (strace filter) and understood (parser + detector). The live end-to-end proof is doctor check 9."""
import pytest

from shadowrun import monitor, policy, sandbox
from shadowrun.detector import DetectorConfig, RunContext, analyze
from shadowrun.monitor import parse_trace

CFG = DetectorConfig.from_policy()
CANARIES = ["/home/sandbox/.ssh/id_rsa", "/home/sandbox/.env"]


def ln(body, pid=7, ts="1.0"):
    return f"{pid} {ts} {body}"


def rules(*bodies, **ctx_kw):
    pr = parse_trace("\n".join(ln(b, ts=f"1.{i}") for i, b in enumerate(bodies)))
    f = analyze(pr.events, RunContext(canary_paths=CANARIES, **ctx_kw), CFG)
    return {x.rule_id for x in f}


# ------------------------------------------------------------------ the filter itself

def test_filter_covers_every_group_and_has_no_duplicates():
    names = [n.lstrip("?") for n in monitor.strace_filter().split(",")]
    assert len(names) == len(set(names))
    for group in (monitor.OPEN_CALLS, monitor.EXEC_CALLS, monitor.CONNECT_CALLS, monitor.SEND_CALLS,
                  monitor.RENAME_LIKE, monitor.SYMLINK_CALLS, monitor.PATH_MUTATORS, monitor.CWD_CALLS,
                  monitor.SPAWN_CALLS, monitor.EVASION_CALLS):
        assert set(group) <= set(names), set(group) - set(names)
    for must in ("openat2", "creat", "sendto", "sendmsg", "sendmmsg", "execveat", "linkat", "renameat2", "memfd_create",
                 "io_uring_setup", "mount", "fchdir"):
        assert must in names, must


def test_optional_names_are_marked_so_an_older_strace_ignores_them():
    f = monitor.strace_filter().split(",")
    assert "?openat2" in f and "?execveat" in f and "openat" in f and "?openat" not in f


def test_the_sandbox_tracer_uses_exactly_that_filter():
    assert monitor.strace_filter() in sandbox.TRACER_SCRIPT


# ------------------------------------------------------------------ file opens that are not openat()

def test_openat2_of_a_canary_is_a_canary_read():
    assert rules('openat2(AT_FDCWD</work>, "/home/sandbox/.ssh/id_rsa", {flags=O_RDONLY|O_CLOEXEC, resolve=0}, 24) = 3</x>') == {"CANARY_READ"}


def test_openat2_write_flags_are_a_write():
    assert rules('openat2(AT_FDCWD</work>, "/home/sandbox/.bashrc", {flags=O_WRONLY|O_CREAT|O_APPEND, mode=0644, resolve=0}, 24) = 3') == {"PERSISTENCE_WRITE"}


def test_creat_is_a_write():
    assert rules('creat("/home/sandbox/.profile", 0644) = 3</home/sandbox/.profile>') == {"PERSISTENCE_WRITE"}
    assert rules('creat("/work/site/x", 0644) = 3') == set()
    assert rules('creat("/home/sandbox/.stash", 0644) = 3') == {"WRITE_OUTSIDE_ALLOWED"}


# ------------------------------------------------------------------ path-changing calls

def test_linkat_and_renameat2_destinations_are_checked_with_their_own_dirfd():
    assert rules('linkat(AT_FDCWD</work>, "/home/sandbox/.profile", AT_FDCWD</work>, "/home/sandbox/.bashrc", 0) = 0') == {"PERSISTENCE_WRITE"}
    # relative destination: the SECOND directory fd decides where it lands
    assert rules('renameat2(5</tmp/a>, "x", 6</home/sandbox>, ".bashrc", 0) = 0') == {"PERSISTENCE_WRITE"}
    assert rules('renameat2(5</home/sandbox>, "x", 6</work/site>, "y", 0) = 0') == set()
    assert rules('link("/tmp/a", "/home/sandbox/.profile") = 0') == {"PERSISTENCE_WRITE"}


def test_symlinkat_uses_the_link_path():
    assert rules('symlinkat("/etc/passwd", 4</home/sandbox>, "link") = 0') == {"WRITE_OUTSIDE_ALLOWED"}
    assert rules('symlinkat("/etc/passwd", AT_FDCWD</work>, "link") = 0') == set()


@pytest.mark.parametrize("call", [
    'fchmodat(AT_FDCWD</work>, "/home/sandbox/x", 0777) = 0', 'fchmodat2(AT_FDCWD</work>, "/home/sandbox/x", 0777, 0) = 0',
    'chown("/home/sandbox/x", 0, 0) = -1 EPERM', 'lchown("/home/sandbox/x", 0, 0) = -1 EPERM',
    'fchownat(AT_FDCWD</work>, "/home/sandbox/x", 0, 0, 0) = -1 EPERM', 'truncate("/home/sandbox/x", 0) = 0',
    'mknod("/home/sandbox/x", S_IFIFO|0600) = 0', 'mknodat(AT_FDCWD</work>, "/home/sandbox/x", S_IFIFO|0600, 0) = 0',
    'rmdir("/home/sandbox/x") = 0', 'unlinkat(AT_FDCWD</work>, "/home/sandbox/x", 0) = 0',
])
def test_every_path_mutator_outside_the_allowed_areas_is_flagged(call):
    assert rules(call) == {"WRITE_OUTSIDE_ALLOWED"}


def test_path_mutators_inside_allowed_areas_are_quiet():
    assert rules('truncate("/work/site/x", 0) = 0', 'rmdir("/tmp/x") = 0', 'mknod("/work/f", S_IFIFO|0600) = 0') == set()


def test_fchdir_changes_the_directory_that_relative_paths_resolve_against():
    pr = parse_trace("\n".join([ln('fchdir(3</home/sandbox>) = 0'), ln('mkdir("evil", 0777) = 0', ts="1.1")]))
    assert [e.path for e in pr.events] == ["/home/sandbox/evil"]


# ------------------------------------------------------------------ network without connect()

SENDTO = 'sendto(3<UDP:[1:2]>, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr("%s")}, 16) = 1'


def test_sendto_to_an_external_or_sink_address_is_outbound_even_without_connect():
    assert rules(SENDTO % (53, "8.8.8.8")) == {"NET_OUTBOUND"}
    assert rules(SENDTO % (9000, "172.18.0.2")) == {"NET_OUTBOUND"}  # datagrams to the sink are still attempts


def test_sendto_loopback_resolver_and_connected_sockets_are_quiet():
    assert rules(SENDTO % (53, "127.0.0.11"), SENDTO % (80, "127.0.0.1")) == set()
    assert rules('sendto(3<TCP:[1]>, "x", 1, 0, NULL, 0) = 1') == set()  # no destination: connect() covered it


def test_sendmsg_and_sendmmsg_destinations_and_ipv6():
    msg4 = ('sendmsg(3<UDP:[1]>, {msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("1.1.1.1")}, '
            'msg_namelen=16, msg_iov=[{iov_base="x", iov_len=1}], msg_iovlen=1}, 0) = 1')
    msg6 = ('sendmmsg(3<UDP:[1]>, [{msg_hdr={msg_name={sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), '
            'inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, msg_namelen=28}, msg_len=1}], 1, 0) = 1')
    assert rules(msg4) == {"NET_OUTBOUND"} and rules(msg6) == {"NET_OUTBOUND"}


def test_the_message_names_the_syscall():
    pr = parse_trace(ln(SENDTO % (53, "8.8.8.8")))
    f = analyze(pr.events, RunContext(canary_paths=[]), CFG)
    assert "sendto" in f[0].message and f[0].evidence["syscall"] == "sendto"


# ------------------------------------------------------------------ exec without execve, and evasion calls

def test_execveat_of_a_path_is_checked_like_execve():
    assert rules('execveat(AT_FDCWD</work>, "/usr/bin/curl", ["curl"], 0x7ff /* 3 vars */, 0) = 0') == {"UNEXPECTED_EXEC"}
    assert rules('execveat(AT_FDCWD</work>, "/usr/bin/git", ["git"], 0x7ff /* 3 vars */, 0) = 0') == set()


def test_execveat_of_a_memfd_is_an_evasion_and_an_unexpected_exec():
    got = rules('execveat(3</memfd:x (deleted)>, "", ["x"], 0x7ff /* 3 vars */, AT_EMPTY_PATH) = -1 ENOEXEC (Exec format error)')
    assert got == {"EVASION_SYSCALL", "UNEXPECTED_EXEC"}


@pytest.mark.parametrize("call", [
    'memfd_create("x", 0) = 3</memfd:x (deleted)>', 'io_uring_setup(4, {flags=0}) = -1 EPERM (Operation not permitted)',
    'io_uring_enter(3, 1, 0, 0, NULL, 0) = -1 EBADF', 'ptrace(PTRACE_ATTACH, 1) = -1 EPERM',
    'process_vm_writev(1, [{iov_base=NULL, iov_len=1}], 1, [{iov_base=NULL, iov_len=1}], 1, 0) = -1 EPERM',
    'mount("none", "/mnt", "tmpfs", 0, NULL) = -1 EPERM (Operation not permitted)', 'umount2("/mnt", 0) = -1 EPERM',
    'pivot_root(".", ".") = -1 EPERM', 'chroot("/tmp") = -1 EPERM', 'unshare(CLONE_NEWUSER) = -1 EPERM',
    'setns(3, 0) = -1 EPERM', 'bpf(BPF_PROG_LOAD, NULL, 0) = -1 EPERM', 'init_module(NULL, 0, "") = -1 EPERM',
    'keyctl(KEYCTL_GET_KEYRING_ID, -1, 0) = -1 EPERM',
])
def test_evasion_syscall_attempts_are_findings_even_when_the_kernel_refuses(call):
    assert rules(call) == {"EVASION_SYSCALL"}


def test_signals_to_the_sandbox_init_or_to_everything_are_findings_other_signals_are_not():
    assert rules("kill(1, SIGKILL) = 0") == {"EVASION_SYSCALL"}
    assert rules("kill(-1, SIGKILL) = 0") == {"EVASION_SYSCALL"}
    assert rules("tgkill(1, 1, SIGKILL) = 0") == {"EVASION_SYSCALL"}
    assert rules("kill(4242, SIGTERM) = 0", "kill(0, SIGTERM) = 0", "tkill(77, SIGINT) = 0") == set()


def test_evasion_syscalls_block():
    pr = parse_trace(ln('memfd_create("x", 0) = 3'))
    f = analyze(pr.events, RunContext(canary_paths=[]), CFG)
    d = policy.decide(f)
    assert d.decision == "BLOCK" and "block_secrets" in d.matched_rules and f[0].severity == "high"


def test_only_the_sandbox_init_may_park_in_cat():
    cat = 'execve("/usr/bin/cat", ["cat"], 0x7ff /* 3 vars */) = 0'
    init_cat = parse_trace(ln(cat, pid=1)).events
    other_cat = parse_trace(ln(cat, pid=9)).events
    c = RunContext(canary_paths=[], init_pid=1)
    assert analyze(init_cat, c, CFG) == []
    assert [f.rule_id for f in analyze(other_cat, c, CFG)] == ["UNEXPECTED_EXEC"]  # a package running cat is judged
    assert [f.rule_id for f in analyze(init_cat, RunContext(canary_paths=[]), CFG)] == ["UNEXPECTED_EXEC"]
