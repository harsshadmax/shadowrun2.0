#!/usr/bin/env bash
# Targeted regression tests for the four security fixes, with real output saved as evidence.
cd "$(dirname "$0")/.."
mkdir -p evidence
OUT=evidence/regression_four_fixes.txt
{
  echo "# Targeted regression tests for the four fixes  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for spec in \
    "BUG 1 shared health status  tests/test_health.py" \
    "BUG 2 trace evidence isolation  tests/test_evidence_isolation.py" \
    "BUG 3 registry allowlist  tests/test_fetcher.py" \
    "BUG 4 incomplete evidence  tests/test_trace_completeness.py" \
    "REVIEW unmonitored syscalls  tests/test_syscall_coverage.py"; do
    file="${spec##* }"
    label="${spec% *}"
    echo; echo "## $label"
    echo "\$ pytest -q $file"
    .venv/bin/python -m pytest -q -p no:cacheprovider "$file" 2>&1 | grep -E "passed|failed|error" | tail -1
  done
  echo; echo "## dashboard consistency tests (doctor pill / panel / run detail)"
  echo "\$ pytest -q tests/test_dashboard.py -k 'health or doctor or pill or stale or busy or detail'"
  .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_dashboard.py -k "health or doctor or pill or stale or busy or detail" 2>&1 | grep -E "passed|failed|error" | tail -1
} | tee "$OUT"
