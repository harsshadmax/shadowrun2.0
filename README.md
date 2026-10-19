# Shadow-Run

A behavioural verification gate for AI coding agents. Before a package install is allowed, Shadow-Run fetches the
package over HTTP, pins its SHA-256, installs it **offline inside an isolated, instrumented Docker sandbox** that
contains fake secrets, watches what the install does (strace + a logging sink), and decides ALLOW, BLOCK or
ESCALATE with a deterministic policy. No LLM is involved in the decision.

**Honest claim.** Shadow-Run reduces the chance and the blast radius of a malicious install. It does not prove
safety. Every number below comes from a small, self-written, simulated benchmark.

Everything here is a **simulation**: the packages, the agent, and the secrets are fake, and payloads can only talk
to a sink container inside an internal Docker network. Nothing touches a real host.

## How it works

```
agent / CLI ──► pipeline ──► fetch (HTTP) ──► sha256 ──► sandbox (internal net, fake home, strace)
                                                          │            │
                                                     strace log     sink log
                                                          └─► detector ─► policy ─► ALLOW | BLOCK | ESCALATE
                                                                              └─► SQLite + hash-chained audit log
```

| Piece | Where |
|---|---|
| Sandbox runner (hardened container settings), `doctor` self-test | `shadowrun/sandbox.py`, `shadowrun/doctor.py` |
| Fake home: canaries (alarm) and decoys (no alarm) | `shadowrun/canary.py` |
| strace parser and rule detector | `shadowrun/monitor.py`, `shadowrun/detector.py` |
| Policy (strictest wins, fails closed) | `shadowrun/policy.py`, `policies/default.yaml` |
| Fetcher (PEP 503, hash pin), pipeline, storage, audit chain | `shadowrun/fetcher.py`, `pipeline.py`, `db.py`, `audit.py` |
| API (FastAPI, SSE), dashboard (Jinja + vendored HTMX/Chart.js) | `shadowrun/api.py`, `ui.py`, `dashboard/` |
| Six simulated packages, built without running their code | `packages/src/*`, `packages/build_all.py` |
| Scripted agent, benchmark, recorded run | `agent/`, `eval/` |

Decisions: **BLOCK** (credential read, exfiltration, persistence write, outbound network during an offline install,
hash mismatch), **ESCALATE** (unexpected exec, writes outside allowed paths, timeout). ESCALATE is treated as
denied and shown as "needs human review". ALLOW always carries "no suspicious behaviour in the tested run (limited
evidence)".

## Setup (Windows 11 + WSL2)

The repo must live in the WSL filesystem (`~/shadow-run`), not under `/mnt/c`.

```bash
# inside Ubuntu on WSL2
sudo apt-get update && sudo apt-get install -y docker.io python3-venv python3-pip strace git
sudo usermod -aG docker $USER      # then: wsl --shutdown (from PowerShell) and reopen Ubuntu
sudo service docker start          # WSL without systemd needs this after each WSL restart

cd ~/shadow-run
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
bash scripts/vendor_assets.sh      # pinned htmx 1.9.12 + Chart.js 4.4.3 (needs internet once)
python packages/build_all.py       # builds the six simulated packages into packages/dist
bash scripts/up.sh                 # images, internal network, sink, pypiserver
python -m shadowrun.cli doctor     # every check must PASS or runs are refused
```

Docker Desktop with WSL integration also works. Docker's internal network and `strace` (ptrace) are required.

## Use

```bash
python -m shadowrun.cli pip install report-export-pro   # exit 2 = BLOCK, 3 = ESCALATE, 0 = ALLOW
python -m shadowrun.cli serve                           # dashboard at http://127.0.0.1:8000
python -m agent.scripted_agent                          # simulated agent against a running server
python -m shadowrun.cli eval --repeats 3                # benchmark -> eval/results/
python -m shadowrun.cli audit verify                    # recompute the audit hash chain
python -m shadowrun.cli reset                           # clear runs/sink/agent events (audit log is kept)
python -m eval.record_run                               # save one full run as a stage backup
python -m pytest                                        # unit tests; sandbox tests skip if services are down
```

## Benchmark (from `eval/results/results.md`)

| Setup | Attacks prevented | Benign wrongly stopped | Canary tokens leaked | Median decision | Max decision |
|---|---|---|---|---|---|
| no_guard | 0 of 3 | 0 of 3 | 3 | n/a | n/a |
| name_check | 1 of 3 | 0 of 3 | 1 | n/a | n/a |
| shadowrun | 2 of 3 | 0 of 3 | 0 | 2.6s | 3.5s |

> Small demo benchmark: 6 self-written, simulated packages, 3 runs each. It shows the mechanism works on simulated
> attacks, not real-world detection rates. Latency is dominated by container start and install time and was
> measured on this machine.

The attack Shadow-Run missed is the time bomb (M3). Acceptance status: see `ACCEPTANCE.md`.

## 5-minute demo script

1. Open `/demo`. The header shows doctor green and "SIMULATED SCENARIOS ONLY".
2. Press **Start demo** (the simulated agent's task is "Add CSV export to the report module"; it proposes `report-export-pro`).
3. Left, no guard: the fake SSH key's canary token reaches the sink, shown in red.
4. Right, Shadow-Run: `CANARY_READ`, `NET_OUTBOUND`, `CANARY_EXFIL`, verdict BLOCKED with measured seconds. The agent reads the reason, switches to `csvtoolkit`, and finishes.
5. On `/`, run a benign scenario (B1 to B3): it passes unchanged.
6. Run **M3 `timekeeper-sync`**: it is allowed. This is the known miss (time bomb); the next step is a deep mode with a shifted clock.
7. Show the benchmark table with counts, latency and the disclaimer.
8. Press **Verify chain** in the audit panel.
9. Close with: "Shadow-Run reduces the chance and the blast radius. It does not prove safety."

Backup if Docker misbehaves on stage: `eval/results/results.md` and `eval/results/recorded_run.md`.

## Known gaps and roadmap (not built)

MODIFY decisions, quick/deep modes and the verdict cache, other evasive packages, replay, approval UI, LLM
explainer, Claude Code hook, shell commands, re-scan, a contained "real install" step, npm, MCP server,
gVisor/Firecracker.

Things to know when reading results:

- **M3 (time bomb) is allowed.** A clock-triggered payload does not fire in the tested run. Known false negative.
- **ALLOW is not a safety proof.** Only behaviour during one offline install in one sandbox is observed.
- **Nothing is installed outside the sandbox** (no "real install" step), so the "leaked tokens: 0" for Shadow-Run is by construction.
- The strace syscall list adds `chdir`, `clone`, `clone3`, `fork`, `vfork` to the blueprint's list so relative paths
  are resolved per process; `AF_UNIX` connects are parsed but not flagged; symlinks are not resolved.
- Sandbox time is container start plus install, measured together.
- Fixtures are assembled by hand (`shadowrun/sdist_tool.py`) because `python -m build` would execute `setup.py` on the host.

## Safety rules

Test packages are inert and labelled SIMULATED; payloads only read fake files and only send to `sink`;
`shadowrun_net` is internal and `doctor` gates every run (fail closed); containers are non-root with
`cap_drop ALL` (plus `SYS_PTRACE` for analysis only), `no-new-privileges`, resource limits, a hard timeout and are
always removed; no Docker socket in containers; all templates are autoescaped and the dashboard JS never builds
HTML from data; any error ends in BLOCK/ESCALATE, never ALLOW.
