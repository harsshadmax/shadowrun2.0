"""HTTP fetch + SHA-256 only. Never `pip download` (it can run setup.py on the host)."""
import hashlib
import re
import shutil
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from . import config

LINK_RE = re.compile(r'<a\s+[^>]*href="([^"]+)"[^>]*>([^<]+)</a>', re.I)
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._+-]+$")


class FetchError(Exception):
    pass


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


def _get(url: str, limit: int = config.MAX_DOWNLOAD_BYTES) -> bytes:
    with urllib.request.urlopen(url, timeout=15) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise FetchError("download exceeds size limit")
    return data


def fetch(spec: str, index: str = config.PYPI_URL) -> FetchResult:
    name, want = parse_spec(spec)
    t0 = time.perf_counter()
    page_url = f"{index}/simple/{normalize(name)}/"
    try:
        html = _get(page_url, 2 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception as e:
        raise FetchError(f"registry lookup failed for {name}: {e}") from e
    cands = []
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
        cands.append((v, fn.endswith(".whl"), fn, urllib.parse.urljoin(page_url, href.split("#")[0])))
    if not cands:
        raise FetchError(f"no matching distribution for {spec}")
    v, _, fn, url = max(cands, key=lambda c: (c[0], c[1]))
    data = _get(url)
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
