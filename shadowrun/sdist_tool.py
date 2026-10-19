"""Hand-assemble an sdist tarball WITHOUT executing any package code.
`python -m build` would run setup.py on the host, which is forbidden for the simulated malicious fixtures."""
import base64
import hashlib
import io
import re
import tarfile
import zipfile
from pathlib import Path

MTIME = 1_700_000_000


def make_wheel(name: str, version: str, files: dict[str, str], outdir: Path, summary: str = "") -> Path:
    """Hand-assemble a pure-Python wheel (zip + dist-info + RECORD). Nothing is executed."""
    outdir.mkdir(parents=True, exist_ok=True)
    dist = re.sub(r"[-_.]+", "_", name)
    out = outdir / f"{dist}-{version}-py3-none-any.whl"
    di = f"{dist}-{version}.dist-info"
    tops = sorted({p.split("/")[0] for p in files if "/" in p})
    allfiles = {
        **files,
        f"{di}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: {summary}\n",
        f"{di}/WHEEL": "Wheel-Version: 1.0\nGenerator: shadowrun-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{di}/top_level.txt": "\n".join(tops) + "\n",
    }
    record = []
    for rel, content in allfiles.items():
        d = base64.urlsafe_b64encode(hashlib.sha256(content.encode()).digest()).rstrip(b"=").decode()
        record.append(f"{rel},sha256={d},{len(content.encode())}")
    record.append(f"{di}/RECORD,,")
    allfiles[f"{di}/RECORD"] = "\n".join(record) + "\n"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, content in sorted(allfiles.items()):
            zi = zipfile.ZipInfo(rel, date_time=(2023, 11, 14, 22, 13, 20))
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, content)
    return out


def make_sdist(name: str, version: str, files: dict[str, str], outdir: Path, summary: str = "") -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    root = f"{name}-{version}"
    out = outdir / f"{root}.tar.gz"
    pkg_info = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: {summary}\n"
    allfiles = {"PKG-INFO": pkg_info, **files}
    with tarfile.open(out, "w:gz") as tf:
        for rel, content in sorted(allfiles.items()):
            data = content.encode()
            ti = tarfile.TarInfo(f"{root}/{rel}")
            ti.size = len(data)
            ti.mtime = MTIME
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    return out
