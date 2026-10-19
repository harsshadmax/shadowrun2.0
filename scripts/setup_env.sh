#!/usr/bin/env bash
set -e
cd ~/shadow-run
touch packages/dist/.gitkeep shadowrun/__init__.py
mkdir -p tests
[ -f tests/test_smoke.py ] || printf 'def test_smoke():\n    assert True\n' > tests/test_smoke.py
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -e . 2>&1 | tail -3
pytest -q 2>&1 | tail -3
git add -A
git commit -qm "step-0: scaffold, CLAUDE.md, blueprint" || true
git log --oneline
