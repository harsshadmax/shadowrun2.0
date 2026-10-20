"""HTTP fetch + SHA-256 only. Never `pip download` (it can run setup.py on the host).

Network policy (security fix): the host talks ONLY to the configured registry origin(s).
  * Every URL, including links found inside registry pages and redirect targets, is validated against an explicit
    allowlist of (scheme, host, port) before anything is sent. Credentials in URLs, lookalike hosts, other ports,
    and alternate IP spellings (127.1, 2130706433, ::ffff:127.0.0.1, trailing dots) are rejected.
  * Hostnames are resolved once, the resolved addresses are checked (no private/loopback/link-local/reserved
    address unless the allowlist entry itself is a loopback/private literal or `localhost`), and the connection is
    then made to that exact IP, so DNS rebinding between check and use cannot redirect the request.
  * Redirects are followed manually (max 3) and every hop goes through the same checks.
The default allowlist is the single origin of `config.PYPI_URL` (the local pypiserver documented in the README);
extra origins must be listed explicitly in SHADOWRUN_REGISTRY_ALLOWLIST.
"""
import hashlib
import http.client
import ipaddress
import re
import shutil
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from . import config

LINK_RE = re.compile(r'<a\s+[^>]*href="([^"]+)"[^>]*>([^<]+)</a>', re.I)
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._+-]+$")
MAX_URL_LEN = 2048
MAX_REDIRECTS = 3
CONNECT_TIMEOUT_S = 15
_BAD_URL_CHARS = re.compile(r"[\x00-\x20\x7f\\]")


class FetchError(Exception):
    pass


# ---------------------------------------------------------------- allowlist

@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str  # lowercase, no trailing dot; IPv6 in compressed form without brackets
    port: int

    @property
    def is_ip_literal(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    @property
    def internal_ok(self) -> bool:
        """Loopback/private addresses are acceptable only when the operator configured such a host explicitly."""
        if self.host == "localhost":
            return True
        try:
            ip = ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return ip.is_loopback or ip.is_private

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


def _split(url: str):
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN or _BAD_URL_CHARS.search(url):
        raise FetchError("malformed URL")
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port  # raises ValueError for junk such as ':8080.evil.com'
    except ValueError as e:
        raise FetchError(f"malformed URL: {e}") from e
    if parts.scheme not in ("http", "https"):
        raise FetchError(f"scheme {parts.scheme!r} is not allowed")
    if not parts.netloc or parts.hostname is None:
        raise FetchError("URL has no host")
    if "@" in parts.netloc:
        raise FetchError("credentials in URLs are not allowed")
    return parts, port


def _normalize_host(host: str) -> str:
    host = host.lower()
    if not host or not host.isascii() or host.endswith("."):
        raise FetchError("host must be non-empty ASCII without a trailing dot")
    try:
        ip = ipaddress.ip_address(host)
        return ip.compressed if ip.version == 6 else str(ip)
    except ValueError:
        return host


def parse_origin(url: str) -> Origin:
    parts, port = _split(url)
    return Origin(parts.scheme, _normalize_host(parts.hostname), port or (443 if parts.scheme == "https" else 80))


def allowlist() -> list[Origin]:
    return [parse_origin(u) for u in config.REGISTRY_ALLOWLIST]


def validate_url(url: str, origins: list[Origin] | None = None) -> tuple[urllib.parse.SplitResult, Origin]:
    """Return (parsed URL, matching allowlist entry) or raise FetchError. No network access."""
    parts, port = _split(url)
    host = _normalize_host(parts.hostname)
    # `127.1`, `2130706433`, `0x7f.1`, `[::ffff:127.0.0.1]` ... never equal the configured spelling, so they fail here
    candidate = Origin(parts.scheme, host, port or (443 if parts.scheme == "https" else 80))
    for o in (origins if origins is not None else allowlist()):
        if candidate == o:
            return parts, o
    raise FetchError(f"{candidate} is not an allowed registry origin")


def resolve_pinned(entry: Origin, host: str, port: int) -> str:
    """Resolve once and return the single IP the connection must use. Rejects disallowed addresses."""
    if entry.is_ip_literal:
        return host
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as e:
        raise FetchError(f"cannot resolve {host}: {e}") from e
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if not entry.internal_ok and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                                      or ip.is_reserved or ip.is_unspecified):
            raise FetchError(f"{host} resolves to a non-public address ({ip}); refusing")
        if entry.internal_ok and entry.host == "localhost" and not ip.is_loopback:
            raise FetchError(f"localhost resolves to a non-loopback address ({ip}); refusing")
        ips.append(ip)
    if not ips:
        raise FetchError(f"{host} did not resolve")
    ips.sort(key=lambda i: i.version)  # prefer IPv4
    return str(ips[0])


# ---------------------------------------------------------------- pinned connections

class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, pin_ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._pin_ip = pin_ip

    def connect(self):
        self.sock = socket.create_connection((self._pin_ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, pin_ip, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._pin_ip = pin_ip

    def connect(self):
        sock = socket.create_connection((self._pin_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # certificate checked for the name


def http_get(url: str, limit: int, origins: list[Origin] | None = None) -> bytes:
    """GET with allowlist, pinned IP and validated redirects. Raises FetchError on any policy violation."""
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        parts, entry = validate_url(current, origins)
        host = _normalize_host(parts.hostname)
        pin = resolve_pinned(entry, host, entry.port)
        cls = _PinnedHTTPS if parts.scheme == "https" else _PinnedHTTP
        conn = cls(parts.hostname, entry.port, pin, CONNECT_TIMEOUT_S)
        try:
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            conn.request("GET", path, headers={"User-Agent": "shadowrun-fetcher", "Accept-Encoding": "identity"})
            resp = conn.getresponse()
            if resp.status in (301, 302, 303, 307, 308):
                loc = resp.getheader("Location")
                if not loc:
                    raise FetchError("redirect without Location")
                current = urllib.parse.urljoin(current, loc)
                continue
            if resp.status != 200:
                raise FetchError(f"registry returned HTTP {resp.status}")
            data = resp.read(limit + 1)
        except FetchError:
            raise
        except (OSError, http.client.HTTPException) as e:
            raise FetchError(f"request failed: {type(e).__name__}: {e}") from e
        finally:
            conn.close()
        if len(data) > limit:
            raise FetchError("download exceeds size limit")
        return data
    raise FetchError("too many redirects")


# ---------------------------------------------------------------- registry client

@dataclass
class FetchResult:
    name: str
    version: str
    filename: str
    path: str
    cache_dir: str
    sha256: str
    fetch_ms: float
    hash_ms: float


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_spec(spec: str) -> tuple[str, str | None]:
    m = re.fullmatch(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==\s*([A-Za-z0-9.+!_-]+))?\s*", spec)
    if not m:
        raise FetchError(f"unsupported spec {spec!r} (use name or name==version)")
    return m.group(1), m.group(2)


def version_of(filename: str) -> str | None:
    if filename.endswith(".whl"):
        parts = filename[:-4].split("-")
        return parts[1] if len(parts) >= 5 else None
    for ext in (".tar.gz", ".zip"):
        if filename.endswith(ext):
            stem = filename[: -len(ext)]
            return stem.rsplit("-", 1)[1] if "-" in stem else None
    return None


def fetch(spec: str, index: str | None = None, origins: list[Origin] | None = None) -> FetchResult:
    """Download `spec` from the registry. `index`/`origins` exist for tests; `index` must be inside the allowlist."""
    index = index or config.PYPI_URL
    allowed = origins if origins is not None else allowlist()
    validate_url(index, allowed)  # refuse before any I/O if the index itself is not allowed
    name, want = parse_spec(spec)
    t0 = time.perf_counter()
    page_url = f"{index.rstrip('/')}/simple/{normalize(name)}/"
    try:
        html = http_get(page_url, 2 * 1024 * 1024, allowed).decode("utf-8", errors="replace")
    except FetchError as e:
        raise FetchError(f"registry lookup failed for {name}: {e}") from e
    cands, rejected = [], []
    for href, text in LINK_RE.findall(html):
        fn = text.strip()
        ver = version_of(fn)
        if not ver or not SAFE_FILENAME.match(fn):
            continue
        try:
            v = Version(ver)
        except InvalidVersion:
            continue
        if want and ver != want:
            continue
        url = urllib.parse.urljoin(page_url, href.split("#")[0])
        try:
            validate_url(url, allowed)  # links inside registry pages are untrusted input
        except FetchError as e:
            rejected.append(f"{fn}: {e}")
            continue
        cands.append((v, fn.endswith(".whl"), fn, url))
    if not cands:
        extra = f" ({len(rejected)} link(s) rejected by the registry allowlist: {rejected[0]})" if rejected else ""
        raise FetchError(f"no matching distribution for {spec}{extra}")
    v, _, fn, url = max(cands, key=lambda c: (c[0], c[1]))
    data = http_get(url, config.MAX_DOWNLOAD_BYTES, allowed)
    fetch_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    sha = hashlib.sha256(data).hexdigest()
    hash_ms = (time.perf_counter() - t1) * 1000
    cache = config.FETCH_DIR / sha
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / fn
    dest.write_bytes(data)
    return FetchResult(name=name, version=str(v), filename=fn, path=str(dest), cache_dir=str(cache),
                       sha256=sha, fetch_ms=fetch_ms, hash_ms=hash_ms)


def cleanup_cache(res: FetchResult) -> None:
    shutil.rmtree(res.cache_dir, ignore_errors=True)
