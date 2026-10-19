#!/usr/bin/env bash
# Shows the Step 6 check with real output: CLI exit codes + agent transcript through a live API.
cd "$(dirname "$0")/.."
PY=.venv/bin/python
echo '$ shadowrun pip install report-export-pro'
$PY -m shadowrun.cli pip install report-export-pro; echo "exit code: $?"
echo
echo '$ shadowrun pip install csvtoolkit'
$PY -m shadowrun.cli pip install csvtoolkit; echo "exit code: $?"
echo
$PY -m shadowrun.cli serve --port 8765 >.data/serve.log 2>&1 &
SRV=$!
for i in $(seq 1 20); do curl -fs http://127.0.0.1:8765/api/v1/health >/dev/null && break; sleep 0.5; done
echo '$ python -m agent.scripted_agent'
SHADOWRUN_API=http://127.0.0.1:8765 $PY -m agent.scripted_agent
kill $SRV
