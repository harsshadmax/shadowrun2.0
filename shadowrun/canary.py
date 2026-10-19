"""Per-run fake home: canaries (alarm) and decoys (no alarm). All values are generated, never real."""
import base64
import os
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import config

CANARY_FILES = {
    "ssh": ".ssh/id_rsa",
    "aws": ".aws/credentials",
    "env": ".env",
    "npm": ".npmrc",
}


@dataclass
class CanarySet:
    run_token: str
    home: Path
    tokens: dict = field(default_factory=dict)  # kind -> token string
    canary_paths: dict = field(default_factory=dict)  # kind -> path inside the sandbox home


def _write(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, mode)


def create_home(run_id: str, sandbox_home: str = "/home/sandbox") -> CanarySet:
    run_token = secrets.token_hex(6)
    home = config.HOMES_DIR / run_id
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True)
    os.chmod(home, 0o755)
    cs = CanarySet(run_token=run_token, home=home)
    tok = {k: f"CANARY-{run_token}-{k}" for k in CANARY_FILES}
    cs.tokens = tok

    filler = base64.b64encode(secrets.token_bytes(120)).decode()
    _write(home / ".ssh/id_rsa",
           f"-----BEGIN OPENSSH PRIVATE KEY-----\n{tok['ssh']}\n{filler}\n-----END OPENSSH PRIVATE KEY-----\n")
    _write(home / ".aws/credentials",
           f"[default]\naws_access_key_id = AKIAFAKE{run_token.upper()}\naws_secret_access_key = {tok['aws']}\n")
    _write(home / ".env", f"DATABASE_URL=postgres://app:{tok['env']}@db.internal/app\nSECRET_KEY={tok['env']}\n")
    _write(home / ".npmrc", f"//registry.npmjs.org/:_authToken={tok['npm']}\n")

    # Decoys: benign tools read these; they must never raise findings.
    _write(home / ".gitconfig", "[user]\n\tname = Test User\n\temail = test@example.invalid\n", 0o644)
    _write(home / ".bash_history", "ls\ncd project\ngit status\n", 0o644)
    _write(home / ".bashrc", "# ~/.bashrc\nalias ll='ls -l'\n", 0o644)
    _write(home / ".profile", "# ~/.profile\n", 0o644)
    _write(home / "project/README.md", "# demo project\n", 0o644)

    cs.canary_paths = {k: f"{sandbox_home}/{rel}" for k, rel in CANARY_FILES.items()}
    return cs


def cleanup_home(cs: CanarySet) -> None:
    shutil.rmtree(cs.home, ignore_errors=True)
