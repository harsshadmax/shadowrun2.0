import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / ".data"
SINK_DIR = DATA / "sink"
SINK_LOG = SINK_DIR / "sink.jsonl"
TRACE_DIR = DATA / "trace"
HOMES_DIR = DATA / "homes"
FETCH_DIR = DATA / "fetch"
DOCTOR_STATE = DATA / "doctor_state.json"

DB_PATH = Path(os.environ.get("SHADOWRUN_DB", ROOT / "shadowrun.db"))
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024

NETWORK = "shadowrun_net"
SANDBOX_IMAGE = "shadowrun-sandbox"
SINK_IMAGE = "shadowrun-sink"
SINK_NAME = "sink"
SINK_PORT = 9000
PYPI_URL = "http://127.0.0.1:8080"  # the local pypiserver started by scripts/up.sh (see README)
# Origins the host may download from. Default: only PYPI_URL. Extra origins must be listed explicitly,
# comma separated, e.g. SHADOWRUN_REGISTRY_ALLOWLIST="http://127.0.0.1:8080,https://pypi.example.org".
REGISTRY_ALLOWLIST = [u.strip() for u in os.environ.get("SHADOWRUN_REGISTRY_ALLOWLIST", PYPI_URL).split(",") if u.strip()]

TIMEOUT_S = 30
UID = os.getuid()
GID = os.getgid()
