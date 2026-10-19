#!/usr/bin/env bash
# Fill the dashboard with real runs: all six fixtures through the gate, plus the unguarded and agent demo.
cd "$(dirname "$0")/.."
PY=.venv/bin/python
$PY -m shadowrun.cli reset >/dev/null
for p in tinyjson-utils csvtoolkit gitversion report-export-pro reqeusts timekeeper-sync; do
  $PY -m shadowrun.cli pip install "$p" | sed -n 2p
done
$PY -m eval.record_run >/dev/null
echo seeded
