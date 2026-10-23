#!/usr/bin/env bash
# Linux/WSL2 validation: environment, doctor, compile check, full pytest, benchmark. Real output, real exit codes.
#
# The evidence is bound to the source that was tested:
#   * it refuses to run on a dirty working tree (only docs, evidence/ and eval/results/ may differ);
#   * the log records the commit, its tree hash, and a content hash of all tracked source files
#     (scripts/source_hash.sh), computed before AND after the run;
#   * the run fails if the source changed while it was running.
# Usage: bash scripts/validate.sh        (set ALLOW_DIRTY=1 to run anyway; the log then says so loudly)
cd "$(dirname "$0")/.."
PY=.venv/bin/python
SRC_PATHS=(. ':(exclude)evidence' ':(exclude)eval/results' ':(exclude)*.md')  # docs and generated evidence do not change behaviour

DIRTY_LIST=$(git status --porcelain --untracked-files=all -- "${SRC_PATHS[@]}")
DIRTY_N=$(printf '%s' "$DIRTY_LIST" | grep -c . || true)
if [ "$DIRTY_N" != 0 ] && [ -z "$ALLOW_DIRTY" ]; then
  echo "refusing to validate: $DIRTY_N uncommitted source file(s). Commit them first (or ALLOW_DIRTY=1):" >&2
  printf '%s\n' "$DIRTY_LIST" >&2
  exit 2
fi

mkdir -p evidence
LOG=evidence/validation.log
: > "$LOG"
say() { printf '\n$ %s\n' "$*" | tee -a "$LOG"; }
run() { say "$*"; "$@" 2>&1 | tee -a "$LOG"; rc=${PIPESTATUS[0]}; echo "[exit code: $rc]" | tee -a "$LOG"; return 0; }

HASH_BEFORE=$(bash scripts/source_hash.sh)
{
  echo "# Shadow-Run validation $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "## Source under test"
  echo "branch:        $(git rev-parse --abbrev-ref HEAD)"
  echo "commit:        $(git rev-parse HEAD)"
  echo "tree:          $(git rev-parse 'HEAD^{tree}')"
  echo "source sha256: $HASH_BEFORE   (bash scripts/source_hash.sh on this commit must print the same)"
  if [ "$DIRTY_N" = 0 ]; then echo "working tree:  CLEAN (nothing uncommitted except docs, evidence/ and eval/results/)";
  else echo "working tree:  DIRTY, $DIRTY_N file(s): the tested source may differ from the commit above"; printf '%s\n' "$DIRTY_LIST"; fi
  echo "## Environment"
  uname -a
  grep PRETTY_NAME /etc/os-release
  $PY --version
  docker version --format 'docker server {{.Server.Version}}, client {{.Client.Version}}'
  docker run --rm --entrypoint strace shadowrun-sandbox -V | head -1
} 2>&1 | tee -a "$LOG"

docker rm -f $(docker ps -aq --filter ancestor=shadowrun-sandbox) >/dev/null 2>&1
bash scripts/up.sh 2>&1 | tail -1 | tee -a "$LOG"
run $PY -m shadowrun.cli doctor
run $PY -m compileall -q shadowrun eval agent packages
run $PY -m pip check
run $PY -m shadowrun.cli reset
run $PY -m pytest -q -rs -p no:cacheprovider
run $PY -m shadowrun.cli reset
run $PY -m shadowrun.cli eval --repeats 3
run $PY -m shadowrun.cli audit verify

HASH_AFTER=$(bash scripts/source_hash.sh)
{
  echo
  echo "## Integrity of the run"
  echo "source sha256 before: $HASH_BEFORE"
  echo "source sha256 after:  $HASH_AFTER"
  if [ "$HASH_BEFORE" = "$HASH_AFTER" ]; then echo "result: source unchanged during validation";
  else echo "result: SOURCE CHANGED DURING VALIDATION: this log is not valid evidence"; fi
  echo "== done $(date -u +%H:%M:%S)"
} | tee -a "$LOG"
[ "$HASH_BEFORE" = "$HASH_AFTER" ]
