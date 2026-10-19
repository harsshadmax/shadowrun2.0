#!/usr/bin/env bash
# Acceptance #17 and #4: the demo runs twice from a reset without manual database fixes; sink publishes no host port.
cd "$(dirname "$0")/.."
PY=.venv/bin/python
for i in 1 2; do
  $PY -m shadowrun.cli reset >/dev/null
  $PY -m eval.record_run > .data/rec$i.txt 2>&1
  echo "recording $i exit code: $?"
  grep -E '^- |Leaked' .data/rec$i.txt | cut -c1-160
done
echo "published ports on sink: [$(docker port sink)]"
$PY -m shadowrun.cli audit verify
