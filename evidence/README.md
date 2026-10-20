# Evidence

Everything here was produced on this machine (Windows 11, WSL2 Ubuntu 24.04, Docker Engine 29.1.3) by the scripts in
`scripts/`. Nothing was edited by hand. All scenarios are SIMULATED.

| File | What it is | Produced by |
|---|---|---|
| `validation.log` | Environment, doctor, compile check, `pip check`, full pytest, 3-repeat benchmark, audit verify, with exit codes | `bash scripts/validate.sh` |
| `regression_four_fixes.txt` | Targeted test runs for the four security fixes | `bash scripts/regression_four_fixes.sh` |
| `demo_run.txt` | The documented safe demo run through the API: fresh doctor check, unguarded install (leak), simulated agent through the gate | `python scripts/run_demo_via_api.py` |
| `demo_status.txt` | Doctor status and latest verdicts read from the live API at one moment: same doctor check id, run ids, times | `python scripts/demo_status.py` |
| `verify_demo_twice.txt` | Reset-then-demo executed twice (acceptance item 17), sink publishes no host port, audit chain OK | `bash scripts/verify_demo_twice.sh` |
| `dashboard_overview.jpg` | Screenshot of the redesigned dashboard after the demo run | in-app browser |
| `split_screen_demo.gif` | Terminal beside dashboard, three frames | assembled from the real terminal output and screenshots above |
| `split_screen_frame*.png` | The same three frames as images (git-ignored) | same |

**About the GIF.** It is a frame-by-frame replay, not a live screen recording: no screen recorder (ffmpeg, OBS,
Chrome) is installed here, and a desktop recording could capture unrelated windows. For a real recording, run
`python -m shadowrun.cli serve`, open <http://127.0.0.1:8000/demo> and record with Windows Game Bar (Win+Alt+R).

**Consistency of the demo state.** The doctor check was refreshed immediately before the demo (`#158c9540cd`,
10:20:51 UTC). Both new runs list that same id as the check that gated them, and the dashboard's header pill and
Sandbox health panel show the same id and time. The older run in `demo_status.txt` is labelled "gated by an earlier
check" on purpose; the dashboard never merges the two.
