import hashlib
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

    def do_GET(self):
        if self.path == "/simple/demo-pkg/":
            links = "".join(f'<a href="../../packages/{n}#sha256=00">{n}</a><br>'
                            for n in FILES if n.startswith("demo_pkg"))
            links += '<a href="../../packages/x">../../etc/passwd-1.0.tar.gz</a>'
            body = f"<html><body>{links}</body></html>".encode()
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


def test_normalize():
    assert fetcher.normalize("Demo_Pkg.X--y") == "demo-pkg-x-y"


def test_latest_version_prefers_wheel_and_hashes(index):
    r = fetcher.fetch("Demo_Pkg", index)
    assert (r.version, r.filename) == ("2.0.0", "demo_pkg-2.0.0-py3-none-any.whl")
    assert r.sha256 == hashlib.sha256(b"wheel-two").hexdigest()
    assert open(r.path, "rb").read() == b"wheel-two"


def test_pinned_version(index):
    r = fetcher.fetch("demo-pkg==1.0.0", index)
    assert r.filename == "demo_pkg-1.0.0.tar.gz"


def test_missing_package_and_version(index):
    with pytest.raises(fetcher.FetchError):
        fetcher.fetch("nope", index)
    with pytest.raises(fetcher.FetchError):
        fetcher.fetch("demo-pkg==9.9", index)


def test_unsafe_filename_ignored_and_bad_spec(index):
    r = fetcher.fetch("demo-pkg", index)
    assert "/" not in r.filename
    with pytest.raises(fetcher.FetchError):
        fetcher.parse_spec("demo-pkg>=1; rm -rf /")
