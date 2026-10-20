import hashlib
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from shadowrun import config, fetcher

FILES = {
    "demo_pkg-1.0.0.tar.gz": b"one",
    "demo_pkg-2.0.0.tar.gz": b"two",
    "demo_pkg-2.0.0-py3-none-any.whl": b"wheel-two",
    "evil-1.0.0.tar.gz": b"x",
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _redirect(self, to):
        self.send_response(302)
        self.send_header("Location", to)
        self.end_headers()

    def do_GET(self):
        if self.path == "/simple/demo-pkg/":
            links = "".join(f'<a href="../../packages/{n}#sha256=00">{n}</a><br>'
                            for n in FILES if n.startswith("demo_pkg"))
            links += '<a href="../../packages/x">../../etc/passwd-1.0.tar.gz</a>'
            # hostile links a compromised registry page might contain
            links += '<a href="http://evil.example/demo_pkg-9.0.0.tar.gz">demo_pkg-9.0.0.tar.gz</a>'
            links += '<a href="http://127.0.0.1:1/demo_pkg-8.0.0.tar.gz">demo_pkg-8.0.0.tar.gz</a>'
            links += '<a href="http://127.0.0.1@evil.example/demo_pkg-7.0.0.tar.gz">demo_pkg-7.0.0.tar.gz</a>'
            body = f"<html><body>{links}</body></html>".encode()
        elif self.path == "/simple/alias-pkg/":
            return self._redirect("/simple/demo-pkg/")  # same-origin redirect: allowed
        elif self.path == "/simple/hostile-redirect/":
            return self._redirect("http://evil.example/simple/demo-pkg/")
        elif self.path == "/simple/trap/":
            body = b'<a href="../../packages/trap-1.0.0.tar.gz">trap-1.0.0.tar.gz</a>'
        elif self.path == "/packages/trap-1.0.0.tar.gz":
            return self._redirect("http://evil.example/payload")
        elif self.path == "/simple/loop/":
            return self._redirect("/simple/loop/")
        elif self.path.startswith("/packages/") and self.path[10:] in FILES:
            body = FILES[self.path[10:]]
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def index(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "FETCH_DIR", tmp_path / "fetch")
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def F(spec, index, **kw):
    return fetcher.fetch(spec, index, origins=[fetcher.parse_origin(index)], **kw)


# ------------------------------------------------------------------ functionality (unchanged behaviour)

def test_normalize():
    assert fetcher.normalize("Demo_Pkg.X--y") == "demo-pkg-x-y"


def test_latest_version_prefers_wheel_and_hashes(index):
    r = F("Demo_Pkg", index)
    assert (r.version, r.filename) == ("2.0.0", "demo_pkg-2.0.0-py3-none-any.whl")
    assert r.sha256 == hashlib.sha256(b"wheel-two").hexdigest()
    assert open(r.path, "rb").read() == b"wheel-two"


def test_pinned_version(index):
    assert F("demo-pkg==1.0.0", index).filename == "demo_pkg-1.0.0.tar.gz"


def test_missing_package_and_version(index):
    with pytest.raises(fetcher.FetchError):
        F("nope", index)
    with pytest.raises(fetcher.FetchError):
        F("demo-pkg==9.9", index)


def test_unsafe_filename_ignored_and_bad_spec(index):
    assert "/" not in F("demo-pkg", index).filename
    with pytest.raises(fetcher.FetchError):
        fetcher.parse_spec("demo-pkg>=1; rm -rf /")


def test_same_origin_redirect_is_followed(index):
    assert F("alias-pkg", index).version == "2.0.0"


# ------------------------------------------------------------------ allowlist: URL validation

ORIGIN = fetcher.parse_origin("http://127.0.0.1:8080")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/simple/x/", "http://127.0.0.1:8080", "HTTP://127.0.0.1:8080/x",
    "http://127.0.0.1:8080/packages/a-1.0.tar.gz?x=1",
])
def test_allowed_urls(url):
    fetcher.validate_url(url, [ORIGIN])


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8081/", "https://127.0.0.1:8080/", "http://127.0.0.1/", "http://evil.example:8080/",
    "http://127.0.0.1.evil.example:8080/", "http://127.0.0.1:8080.evil.example/",
    "http://127.0.0.1:8080@evil.example/", "http://user:pw@127.0.0.1:8080/",
    "http://127.0.0.1:8080\\@evil.example/", "http://127.0.0.1.:8080/",
    "http://127.1:8080/", "http://2130706433:8080/", "http://0x7f.0.0.1:8080/", "http://0177.0.0.1:8080/",
    "http://[::1]:8080/", "http://[::ffff:127.0.0.1]:8080/", "http://localhost:8080/", "http://127.0.0.2:8080/",
    "ftp://127.0.0.1:8080/", "file:///etc/passwd", "//evil.example/x", "/relative/path", "", "http://",
    "http://127.0.0.1:99999/", "http://127.0.0.1:8080/\x00", "http://127.0.0.1:8080/a b",
    "http://127.0.0.1:8080/" + "a" * 3000, "http://127.0.0.1:８０８０/",
])
def test_rejected_urls(url):
    with pytest.raises(fetcher.FetchError):
        fetcher.validate_url(url, [ORIGIN])


def test_non_string_rejected():
    with pytest.raises(fetcher.FetchError):
        fetcher.validate_url(None, [ORIGIN])  # type: ignore[arg-type]


def test_ipv6_allowlist_entry_and_spellings():
    o6 = fetcher.parse_origin("http://[::1]:8080")
    fetcher.validate_url("http://[::1]:8080/x", [o6])
    fetcher.validate_url("http://[0:0:0:0:0:0:0:1]:8080/x", [o6])  # same address, canonical form compared
    for bad in ("http://[::2]:8080/", "http://[::ffff:127.0.0.1]:8080/", "http://127.0.0.1:8080/"):
        with pytest.raises(fetcher.FetchError):
            fetcher.validate_url(bad, [o6])


def test_default_allowlist_is_exactly_the_configured_registry():
    assert config.REGISTRY_ALLOWLIST == [config.PYPI_URL]
    assert fetcher.allowlist() == [fetcher.parse_origin(config.PYPI_URL)]


# ------------------------------------------------------------------ allowlist: behaviour during fetch

def test_hostile_links_in_registry_page_are_ignored(index):
    r = F("demo-pkg", index)  # 9.0.0 / 8.0.0 / 7.0.0 point at hostile locations and must not win
    assert r.version == "2.0.0"


@pytest.mark.parametrize("ver", ["9.0.0", "8.0.0", "7.0.0"])
def test_pinning_a_version_that_only_exists_on_a_hostile_link_fails(index, ver):
    with pytest.raises(fetcher.FetchError, match="rejected by the registry allowlist"):
        F(f"demo-pkg=={ver}", index)


def test_no_connection_is_ever_attempted_to_a_hostile_host(index, monkeypatch):
    real = socket.create_connection
    targets = []

    def spy(addr, *a, **kw):
        targets.append(addr)
        return real(addr, *a, **kw)
    monkeypatch.setattr(socket, "create_connection", spy)
    F("demo-pkg", index)
    assert targets and all(t[0] == "127.0.0.1" and t[1] == int(index.rsplit(":", 1)[1]) for t in targets)


def test_redirect_to_hostile_host_on_page_is_refused(index):
    with pytest.raises(fetcher.FetchError, match="not an allowed registry origin"):
        F("hostile-redirect", index)


def test_redirect_to_hostile_host_on_file_download_is_refused(index):
    with pytest.raises(fetcher.FetchError, match="not an allowed registry origin"):
        F("trap", index)


def test_redirect_loop_is_bounded(index):
    with pytest.raises(fetcher.FetchError, match="too many redirects"):
        F("loop", index)


def test_index_outside_allowlist_is_refused_before_any_io(monkeypatch):
    def boom(*a, **kw):
        raise AssertionError("network used")
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(fetcher.FetchError, match="not an allowed registry origin"):
        fetcher.fetch("anything", "http://evil.example", origins=[ORIGIN])
    with pytest.raises(fetcher.FetchError):
        fetcher.fetch("anything", "http://127.0.0.1:9", origins=[ORIGIN])


def test_download_size_limit(index):
    with pytest.raises(fetcher.FetchError, match="size limit"):
        fetcher.http_get(f"{index}/packages/demo_pkg-1.0.0.tar.gz", 2, [fetcher.parse_origin(index)])


# ------------------------------------------------------------------ DNS: rebinding, private ranges, pinning

NAMED = fetcher.parse_origin("http://registry.example")


def gai(*ips):
    def fake(host, port, *a, **kw):
        fake.calls += 1
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in ips]
    fake.calls = 0
    return fake


@pytest.mark.parametrize("ips", [["127.0.0.1"], ["10.0.0.5"], ["192.168.1.9"], ["169.254.169.254"], ["0.0.0.0"],
                                 ["::1"], ["fe80::1"], ["fd00::1"], ["::ffff:10.0.0.1"], ["224.0.0.1"],
                                 ["8.8.8.8", "10.0.0.1"]])
def test_named_registry_resolving_to_internal_or_mixed_addresses_is_refused(monkeypatch, ips):
    monkeypatch.setattr(socket, "getaddrinfo", gai(*ips))
    with pytest.raises(fetcher.FetchError, match="non-public"):
        fetcher.resolve_pinned(NAMED, "registry.example", 80)


def test_public_address_is_accepted_and_ipv4_preferred(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", gai("2606:4700::1111", "93.184.216.34"))
    assert fetcher.resolve_pinned(NAMED, "registry.example", 80) == "93.184.216.34"


def test_localhost_entry_must_resolve_to_loopback(monkeypatch):
    local = fetcher.parse_origin("http://localhost:8080")
    monkeypatch.setattr(socket, "getaddrinfo", gai("127.0.0.1"))
    assert fetcher.resolve_pinned(local, "localhost", 8080) == "127.0.0.1"
    monkeypatch.setattr(socket, "getaddrinfo", gai("10.0.0.5"))
    with pytest.raises(fetcher.FetchError, match="non-loopback"):
        fetcher.resolve_pinned(local, "localhost", 8080)


def test_dns_failure_is_a_fetch_error(monkeypatch):
    def fail(*a, **kw):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(fetcher.FetchError, match="cannot resolve"):
        fetcher.resolve_pinned(NAMED, "registry.example", 80)


def test_connection_goes_to_the_validated_ip_and_dns_is_asked_once(monkeypatch):
    """Rebinding: the first answer is public, any later answer would be internal. We must use the first, once."""
    answers = [["93.184.216.34"], ["127.0.0.1"]]
    calls = {"n": 0}

    def rebinding(host, port, *a, **kw):
        ips = answers[min(calls["n"], 1)]
        calls["n"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ips[0], port))]
    seen = []

    def fake_connect(addr, *a, **kw):
        seen.append(addr)
        raise OSError("blocked by test")
    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    monkeypatch.setattr(socket, "create_connection", fake_connect)
    with pytest.raises(fetcher.FetchError):
        fetcher.http_get("http://registry.example/simple/x/", 1000, [NAMED])
    assert calls["n"] == 1 and seen == [("93.184.216.34", 80)]


def test_https_uses_pinned_ip_with_name_verification(monkeypatch):
    o = fetcher.parse_origin("https://registry.example")
    monkeypatch.setattr(socket, "getaddrinfo", gai("93.184.216.34"))
    seen = []

    def fake_connect(addr, *a, **kw):
        seen.append(addr)
        raise OSError("blocked by test")
    monkeypatch.setattr(socket, "create_connection", fake_connect)
    with pytest.raises(fetcher.FetchError):
        fetcher.http_get("https://registry.example/simple/x/", 1000, [o])
    assert seen == [("93.184.216.34", 443)]
    conn = fetcher._PinnedHTTPS("registry.example", 443, "93.184.216.34", 5)
    assert conn._context.check_hostname is True and conn._context.verify_mode.name == "CERT_REQUIRED"
