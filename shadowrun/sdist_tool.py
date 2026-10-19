"""Hand-assemble an sdist tarball WITHOUT executing any package code.
`python -m build` would run setup.py on the host, which is forbidden for the simulated malicious fixtures."""
import io
import tarfile
from pathlib import Path

MTIME = 1_700_000_000


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
