# Shadow-Run

**A behavioural verification gate for AI coding agents.** Before an agent's `pip install` is allowed, Shadow-Run
runs the package inside a locked-down sandbox full of fake secrets, watches what it actually does, and decides
**ALLOW**, **BLOCK** or **ESCALATE** with a deterministic policy. No LLM is in the decision path.

> **Honest claim.** Shadow-Run reduces the chance and the blast radius of a malicious install. It does not prove
> safety. Every number here comes from a small, self-written, simulated benchmark.
>
> Everything is a **simulation**: the packages, the agent and the secrets are fake, and payloads can only reach a
> sink container inside an internal Docker network. Nothing touches a real host.

![Dashboard overview](eval/results/dashboard_overview.jpg)

## Contents

1. [The problem and the idea](#1-the-problem-and-the-idea)
2. [The system at a glance](#2-the-system-at-a-glance)
3. [Anatomy of one scan](#3-anatomy-of-one-scan)
4. [Isolation: what the sandbox can and cannot reach](#4-isolation-what-the-sandbox-can-and-cannot-reach)
5. [What is detected and how it is decided](#5-what-is-detected-and-how-it-is-decided)
6. [The simulated attacks](#6-the-simulated-attacks)
7. [The agent story](#7-the-agent-story)
8. [Audit trail](#8-audit-trail)
9. [Benchmark](#9-benchmark)
10. [Setup, use and demo](#10-setup-use-and-demo)
11. [Known gaps](#11-known-gaps)
12. [Repository map and safety rules](#12-repository-map-and-safety-rules)

---

## 1. The problem and the idea

AI coding agents install packages on their own. A name check or a vulnerability list will not catch a package whose
`setup.py` quietly reads `~/.ssh/id_rsa` the moment it is installed. Shadow-Run looks at **behaviour** instead of
reputation.

```mermaid
flowchart LR
    A["Agent asks: pip install X"] --> G{"Shadow-Run gate"}
    G -->|"1. run X in a trap<br>full of fake secrets"| S["Sandbox"]
    S -->|"2. what did it touch?<br>who did it call?"| E["Evidence"]
    E --> P{"Policy"}
    P -->|"clean"| OK["ALLOW"]
    P -->|"reads secrets, phones home,<br>persists, hash mismatch"| NO["BLOCK"]
    P -->|"odd but unclear"| REV["ESCALATE<br>needs human review"]
```

The trap works because the secrets are **canaries**: unique, fake values (`CANARY-<run>-ssh`). If one ever shows up
in the sink's log, we know exactly which file was stolen and sent.

---

## 2. The system at a glance

```mermaid
flowchart TB
    subgraph clients["Entry points"]
        CLI["CLI<br>shadowrun pip install"]
        AG["Scripted agent<br>SIMULATED"]
        UI["Dashboard<br>FastAPI + HTMX"]
    end

    subgraph host["Host: trusted code only, never package code"]
        API["API + SSE<br>one run at a time"]
        PIPE["Pipeline"]
        FETCH["Fetcher<br>HTTP + SHA-256 pin"]
        DET["Parser + detector"]
        POL["Policy<br>strictest wins, fails closed"]
        DB[("SQLite<br>runs, findings")]
        AUD[("Audit log<br>hash chained")]
        REG[("Local pypiserver<br>6 simulated packages")]
    end

    subgraph net["Docker network shadowrun_net: internal, no internet"]
        SB["Analysis sandbox<br>strace, fake home"]
        EX["Exposed container<br>baselines only"]
        SK["Sink<br>logs every request"]
    end

    CLI --> PIPE
    AG --> API
    UI --> API
    API --> PIPE
    PIPE --> FETCH
    REG -->|"HTTP download only"| FETCH
    FETCH -->|"file, mounted read-only"| SB
    SB -->|"strace log"| DET
    SB -.->|"any request"| SK
    SK -->|"sink log on disk"| DET
    DET --> POL
    POL --> DB
    POL --> AUD
    PIPE -.->|"baseline runs"| EX
    EX -.-> SK
```

| Layer | Job | Code |
|---|---|---|
| Fetcher | Download over HTTP, hash it. **Never** `pip download` (it can run `setup.py` on the host). | `shadowrun/fetcher.py` |
| Sandbox | Hardened container: read-only root, non-root user, no capabilities, no Docker socket, memory/CPU/pid limits, 30 s timeout. | `shadowrun/sandbox.py` |
| Canaries | Per-run fake home with alarming canaries and quiet decoys. | `shadowrun/canary.py` |
| Detector | Parse strace and sink logs, fire rules on **attempts**, not outcomes. | `shadowrun/monitor.py`, `detector.py` |
| Policy | YAML rules, strictest decision wins, any error denies. | `shadowrun/policy.py`, `policies/default.yaml` |
| Storage | Runs, findings, agent events, benchmark rows, hash-chained audit. | `shadowrun/db.py`, `audit.py` |
| Doctor | Self-test that gates every run. | `shadowrun/doctor.py` |

---

## 3. Anatomy of one scan

What happens between "install this" and the verdict (about 2.5 to 3 seconds once the sandbox is warm).

```mermaid
sequenceDiagram
    autonumber
    participant Ag as Agent or CLI
    participant Gate as Pipeline
    participant Reg as Local registry
    participant Sbx as Analysis sandbox
    participant Sink as Sink
    participant Rules as Detector and policy
    participant Log as Audit log

    Ag->>Gate: install report-export-pro
    Gate->>Log: ACTION_RECEIVED
    Gate->>Gate: doctor must pass (else refuse)
    Gate->>Reg: GET /simple/report-export-pro/
    Reg-->>Gate: file bytes
    Gate->>Gate: SHA-256 pin
    Gate->>Log: FETCHED (name, version, sha256)
    Gate->>Sbx: start with fake home, file mounted read-only
    Note over Sbx: offline pip install,<br>hash required, under strace
    Sbx->>Sbx: setup.py opens ~/.ssh/id_rsa
    Sbx->>Sink: POST /collect with the key
    Sbx-->>Gate: strace log
    Sink-->>Gate: requests from the sandbox's IP
    Gate->>Log: SANDBOX_FINISHED
    Gate->>Rules: events plus sink data
    Rules-->>Gate: CANARY_READ, NET_OUTBOUND, CANARY_EXFIL
    Gate->>Log: FINDINGS_RECORDED, DECISION_MADE
    Gate-->>Ag: BLOCKED, with the evidence
```

Phases are timed individually (fetch, hash, sandbox, analyze, decide) and shown live in the dashboard.

---

## 4. Isolation: what the sandbox can and cannot reach

The trap only works if nothing can escape it. `shadowrun doctor` proves each arrow below before every run.

```mermaid
flowchart LR
    subgraph sbx["Analysis container (non-root, read-only root, no capabilities except ptrace for strace)"]
        PKG["Package code<br>runs during install"]
        HOME["Fake home<br>canaries + decoys"]
        TR["strace<br>records open, connect, exec, writes"]
    end
    SINK["Sink<br>logs, never answers with data"]
    NET["Real internet"]
    HOST["Host files, Docker socket"]

    PKG -->|"reads / writes"| HOME
    PKG -->|"allowed: the only route out"| SINK
    PKG -. "blocked: internal network,<br>no route, no DNS" .-x NET
    PKG -. "blocked: nothing mounted,<br>no socket" .-x HOST
    TR -. "observes" .-> PKG
```

| Control | Setting | Checked by doctor |
|---|---|---|
| Network | `shadowrun_net` is `internal=True` | Internal flag, `1.1.1.1` unreachable, `example.com` does not resolve |
| Sink reachable | Sandbox can POST to `sink:9000` only | Round trip logged by the sink |
| Observation | `strace -f` with a pinned syscall list | Records a canary `openat` and a `connect` |
| Filesystem | Read-only root, `/tmp` and `/work` as tmpfs, fake home writable | Write to `/etc` fails, `/tmp` is executable |
| Privileges | Non-root, `cap_drop ALL` (+ `SYS_PTRACE` for analysis), `no-new-privileges` | Container settings |
| Limits | 512 MB, 1 CPU, 128 pids, 30 s timeout, container always removed | Timeout test |

If any doctor check fails, **runs are refused** (fail closed).

---

## 5. What is detected and how it is decided

### Detector rules

| Rule | Fires when | Severity |
|---|---|---|
| `CANARY_EXFIL` | A canary token for this run appears in the sink's data | critical |
| `HASH_MISMATCH` | pip rejects the file against the pinned SHA-256 | critical |
| `CANARY_READ` | Package code opens a canary file (even if the open fails) | high |
| `NET_OUTBOUND` | Any `connect` except loopback and the resolver (the install is offline, so none is legitimate) | high |
| `PERSISTENCE_WRITE` | Write to `.bashrc`, `.profile`, autostart, cron, `authorized_keys` | high |
| `UNEXPECTED_EXEC` | `execve` of a binary outside the allowed list | medium |
| `WRITE_OUTSIDE_ALLOWED` | Write outside `/work`, `/tmp`, `/home/sandbox/.cache` | medium |
| `SANDBOX_TIMEOUT` | Run exceeded the timeout | medium |
| `INSTALL_FAILED` | pip failed for another reason | low |

Reading a **decoy** (`.gitconfig`, `.bash_history`, ...) is never a finding, so a benign `git` call does not trigger
the gate. Detection is calibrated so that pip's own activity yields zero findings on a real wheel and a real sdist.

### From findings to a verdict

```mermaid
flowchart TD
    F["All findings from the run"] --> R1{"CANARY_EXFIL or<br>HASH_MISMATCH?"}
    F --> R2{"CANARY_READ, PERSISTENCE_WRITE<br>or NET_OUTBOUND?"}
    F --> R3{"UNEXPECTED_EXEC, WRITE_OUTSIDE_ALLOWED<br>or SANDBOX_TIMEOUT?"}
    F --> R4{"Worst severity<br>low or none?"}
    R1 -->|"yes"| B["BLOCK"]
    R2 -->|"yes"| B
    R3 -->|"yes"| E["ESCALATE<br>treated as denied"]
    R4 -->|"yes"| A["ALLOW<br>limited evidence"]
    B --> W{"Strictest wins<br>BLOCK > ESCALATE > ALLOW"}
    E --> W
    A --> W
    W --> OUT["Final decision plus every matched rule"]
    ERR["Any error:<br>bad policy, doctor failure,<br>fetch failure, no trace"] -->|"never ALLOW"| DENY["BLOCK or ESCALATE"]
```

All matching rules are recorded, and an ALLOW always carries the words *"no suspicious behaviour in the tested run
(limited evidence)"*.

---

## 6. The simulated attacks

Six fixtures live in `packages/src`. They are assembled **by hand** (`shadowrun/sdist_tool.py`), because
`python -m build` would execute `setup.py` on your machine. Every file starts with
`# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.`

```mermaid
flowchart LR
    subgraph benign["Benign: expected ALLOW"]
        B1["B1 tinyjson-utils<br>pure Python wheel"]
        B2["B2 csvtoolkit<br>plain setup.py"]
        B3["B3 gitversion<br>setup.py runs git<br>false-positive test"]
    end
    subgraph evil["Malicious"]
        M1["M1 report-export-pro<br>reads SSH key, POSTs it"]
        M2["M2 reqeusts<br>typosquat: edits .bashrc,<br>steals .env + AWS keys"]
        M3["M3 timekeeper-sync<br>time bomb, fires in 180 days"]
    end
    M1 -->|"BLOCK"| X1["CANARY_READ, NET_OUTBOUND, CANARY_EXFIL"]
    M2 -->|"BLOCK"| X2["+ PERSISTENCE_WRITE"]
    M3 -->|"ALLOW: known miss"| X3["payload never fires in the tested run"]
```

M3 is a **known false negative**: a clock-triggered payload does not run now. The planned fix is a deep mode that
shifts the sandbox clock.

---

## 7. The agent story

The simulated agent's task is *"Add CSV export to the report module."* Without the gate it would install the
stealer. With the gate it is stopped, reads the reason, and picks a safe alternative.

```mermaid
sequenceDiagram
    autonumber
    participant Ag as Simulated agent
    participant Gate as Shadow-Run
    Ag->>Ag: PROPOSE report-export-pro
    Ag->>Gate: submit install, wait for verdict
    Gate-->>Ag: BLOCKED (CANARY_READ, NET_OUTBOUND, CANARY_EXFIL)
    Ag->>Ag: BLOCKED_NOTICE with the reason
    Ag->>Ag: CHOOSE_ALT csvtoolkit
    Ag->>Gate: submit install, wait for verdict
    Gate-->>Ag: ALLOWED (limited evidence)
    Ag->>Ag: CONTINUE, write report_export.py
```

The dashboard's **Split-screen demo** shows both worlds side by side:

```mermaid
flowchart LR
    subgraph L["Without Shadow-Run"]
        L1["Package installs<br>into the dev environment"] --> L2["Fake SSH key reaches the<br>attacker's sink: LEAKED"]
    end
    subgraph R["With Shadow-Run"]
        R1["Install runs in the sandbox"] --> R2["BLOCKED with evidence"] --> R3["Agent switches to csvtoolkit"] --> R4["Task finished safely"]
    end
```

---

## 8. Audit trail

Every pipeline step appends an entry to an **insert-only** table. Each entry's hash covers the previous entry's hash,
so editing or deleting any row breaks every hash after it.

```mermaid
flowchart LR
    G["GENESIS"] --> E1["Entry 1<br>ACTION_RECEIVED<br>hash = H(GENESIS, ts, type, run, payload)"]
    E1 --> E2["Entry 2<br>FETCHED<br>hash = H(hash 1, ...)"]
    E2 --> E3["Entry 3<br>SANDBOX_FINISHED<br>hash = H(hash 2, ...)"]
    E3 --> E4["Entry 4<br>DECISION_MADE<br>hash = H(hash 3, ...)"]
    V["audit verify<br>recomputes the chain"] -. "first mismatch = tampered row" .-> E3
```

Event types: `ACTION_RECEIVED`, `FETCHED`, `SANDBOX_STARTED`, `SANDBOX_FINISHED`, `FINDINGS_RECORDED`,
`DECISION_MADE`, `EVAL_STARTED`, `EVAL_FINISHED`. The dashboard's **Verify chain** button and
`shadowrun audit verify` both run the check. Limit: a chain proves *edits* happened, not that the latest rows were
never truncated.

---

## 9. Benchmark

Three setups run over the six fixtures, three repeats each, after one discarded warm-up (`eval/results/results.md`).

```mermaid
flowchart LR
    S["6 simulated packages"] --> N["no_guard<br>install in exposed container"]
    S --> C["name_check<br>blocklist + edit distance to popular names"]
    S --> SR["shadowrun<br>full pipeline"]
    N --> M["Counts from the database:<br>attacks stopped, benign wrongly stopped,<br>canary tokens leaked, decision latency"]
    C --> M
    SR --> M
```

| Setup | Attacks stopped | Benign wrongly stopped | Canary tokens leaked | Median decision | Max decision |
|---|---|---|---|---|---|
| no_guard | 0 of 3 | 0 of 3 | 3 | n/a | n/a |
| name_check | 1 of 3 (the typosquat) | 0 of 3 | 1 | n/a | n/a |
| shadowrun | 2 of 3 (the time bomb slips through) | 0 of 3 | 0 | 2.6 s | 3.5 s |

> Small demo benchmark: 6 self-written, simulated packages, 3 runs each. It shows the mechanism works on simulated
> attacks, not real-world detection rates. Latency is dominated by container start and install time and was measured
> on this machine.

Reading the table honestly: Shadow-Run's `0` leaked tokens is true **by construction**, because it never installs
outside its sandbox. The attack it missed is M3. The name check only caught the one attack with a lookalike name.

---

## 10. Setup, use and demo

### Setup (Windows 11 + WSL2)

The repo must live in the WSL filesystem (`~/shadow-run`), not under `/mnt/c`.

```bash
# inside Ubuntu on WSL2
sudo apt-get update && sudo apt-get install -y docker.io python3-venv python3-pip strace git
sudo usermod -aG docker $USER      # then: wsl --shutdown (from PowerShell) and reopen Ubuntu
sudo service docker start          # WSL without systemd needs this after each WSL restart

git clone https://github.com/harsshadmax/shadowrun.git ~/shadow-run && cd ~/shadow-run
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
bash scripts/vendor_assets.sh      # only if dashboard/static/vendor is missing (needs internet once)
python packages/build_all.py       # builds the six simulated packages into packages/dist
bash scripts/up.sh                 # images, internal network, sink, pypiserver
python -m shadowrun.cli doctor     # every check must PASS or runs are refused
```

Docker Desktop with WSL integration also works.

### Use

```bash
python -m shadowrun.cli pip install report-export-pro   # exit 2 = BLOCK, 3 = ESCALATE, 0 = ALLOW
python -m shadowrun.cli serve                           # dashboard at http://127.0.0.1:8000
python -m agent.scripted_agent                          # simulated agent against a running server
python -m shadowrun.cli eval --repeats 3                # benchmark -> eval/results/
python -m shadowrun.cli audit verify                    # recompute the audit hash chain
python -m shadowrun.cli reset                           # clear runs, sink log, agent events (audit log kept)
python -m eval.record_run                               # save one full run as a stage backup
python -m pytest                                        # sandbox tests skip if the services are down
```

### The dashboard

| Panel | Shows | Source |
|---|---|---|
| Stat cards | Total scans, blocked, allowed | `runs` table |
| Detection matrix | Which rules fired for which package (Findings tab) or decisions per package | `findings`, `runs` |
| Run detail | Timeline per phase, evidence, decision time for the selected run | `runs.phase_ms_json` |
| Isolation | Layout plus the doctor's four sandbox checks | `doctor` |
| Scripted agent | Last transcript lines and a play button | `agent_events` |
| Recent activity | Filter tabs, paging, click a row for its detail | `runs` |
| Demo page | Split-screen demo, benchmark table and chart, audit "Verify chain" | `eval/results/latest.json`, `audit` |

### 5-minute demo script

1. Open `/demo`. The header shows doctor green and **SIMULATED SCENARIOS ONLY**.
2. Press **Start demo**. The simulated agent proposes `report-export-pro`.
3. Left, no guard: the fake SSH key's canary token reaches the sink, shown in red.
4. Right, Shadow-Run: `CANARY_READ`, `NET_OUTBOUND`, `CANARY_EXFIL`, verdict **BLOCKED** with measured seconds. The agent reads the reason, switches to `csvtoolkit`, and finishes.
5. On the overview, **Run scan** a benign package (B1 to B3): it passes unchanged.
6. Run **M3 `timekeeper-sync`**: it is allowed. Say this is the known miss and that a clock-shifting deep mode is the next step.
7. Show the benchmark table with counts, latency and the disclaimer.
8. Press **Verify chain** in the audit panel.
9. Close with: "Shadow-Run reduces the chance and the blast radius. It does not prove safety."

Backup if Docker misbehaves on stage: `eval/results/results.md` and `eval/results/recorded_run.md`.

---

## 11. Known gaps

**Not built (roadmap):** MODIFY decisions, quick/deep modes and the verdict cache, other evasive packages, replay,
approval UI, LLM explainer, Claude Code hook, shell commands, re-scan, a contained "real install" step, npm, MCP
server, gVisor or Firecracker.

**Read results with these in mind:**

- **M3 (time bomb) is allowed.** A clock-triggered payload does not fire in the tested run. Known false negative.
- **ALLOW is not a safety proof.** Only behaviour during one offline install in one sandbox is observed.
- **Nothing is installed outside the sandbox**, so "leaked tokens: 0" for Shadow-Run is by construction.
- The strace syscall list adds `chdir`, `clone`, `clone3`, `fork`, `vfork` to the blueprint's list so relative paths
  resolve per process. `AF_UNIX` connects are parsed but not flagged. Symlinks are not resolved.
- `sandbox` time is container start plus install, measured together. A first scan after an idle period also
  includes the doctor self-test, so it shows a longer decision time.
- Fixtures are assembled by hand because building them would run `setup.py` on the host.
- The dashboard is dark-only.

Acceptance status for all 17 blueprint items is in [`ACCEPTANCE.md`](ACCEPTANCE.md).

---

## 12. Repository map and safety rules

```
shadowrun/        sandbox, canary, monitor, detector, policy, fetcher, pipeline, db, audit, doctor, api, ui, stats, cli
sink/  docker/    sink service and the sandbox image
packages/         simulated fixtures (src) and build_all.py
policies/         default.yaml (rules, allowed paths, pip baseline)
agent/            scripted_agent.py (SIMULATED)
eval/             baselines, run_eval, record_run, results/
dashboard/        Jinja templates, CSS, JS, vendored htmx + Chart.js
scripts/          up/down, vendor_assets, demo helpers
tests/            unit, detector fixtures, API, dashboard, end-to-end through the real sandbox
```

**Safety rules.** Test packages are inert and labelled SIMULATED; payloads only read fake files and only send to
`sink`; `shadowrun_net` is internal and `doctor` gates every run (fail closed); containers are non-root with
`cap_drop ALL` (plus `SYS_PTRACE` for analysis only), `no-new-privileges`, resource limits and a hard timeout, and are
always removed; no Docker socket in containers; all templates are autoescaped and the dashboard JS never builds HTML
from data; any error ends in BLOCK or ESCALATE, never ALLOW.
