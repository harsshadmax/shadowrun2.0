# Shadow-Run

Behavioural verification gate for AI coding agents: a package install is first run inside an isolated, instrumented Docker sandbox; the observed behaviour decides ALLOW / BLOCK / ESCALATE. Full spec: `shawdows2blueprint.md` (this file wins over any older blueprint).

## Honest claim
Shadow-Run reduces the chance and blast radius of a malicious install. It does not prove safety. All numbers come from a small, self-written, simulated benchmark. Never claim more.

## Safety rules (override everything)
1. Test packages are inert, start with `# SIMULATED TEST FIXTURE. INERT OUTSIDE THE SHADOW-RUN SANDBOX.`; names are plausible, "SIMULATED" lives in description/manifest.
2. Payloads only read fake files in the sandbox and only send to hostname `sink`.
3. `shadowrun_net` is `internal=True`. `doctor` must pass before any run; otherwise refuse (fail closed).
4. No Docker socket in containers; non-root; cap_drop ALL (+SYS_PTRACE for analysis only); no-new-privileges; mem/CPU/pids limits; hard timeout; always remove containers.
5. Package names, metadata, sink contents are untrusted: Jinja autoescape everywhere.
6. Any error ends in BLOCK/ESCALATE, never ALLOW. No LLM in the decision path.

## Rules of work
- Never run package code on the host. Fetch = HTTP + hash only (never `pip download`).
- Fail closed.
- Run tests (`pytest`) after every change.
- If Docker/strace behaviour is uncertain, run a small experiment instead of guessing.
- Work step by step per blueprint section 14; each step ends with its check, real output shown, and one commit `step-N: ...`.
- Keep the repo in the WSL filesystem (`~/shadow-run`).

## Layout
`shadowrun/` (cli, config, models, fetcher, sandbox, canary, monitor, detector, policy, audit, pipeline, db, api), `sink/`, `docker/`, `packages/`, `policies/default.yaml`, `agent/`, `dashboard/`, `eval/`, `scripts/`, `.data/` (gitignored), `tests/fixtures/`.

## Commands
- `pytest` — tests
- `python -m shadowrun.cli doctor | up | down | serve | eval | reset`
- `python -m shadowrun.cli pip install <spec>` (exit 0 ALLOW, 2 BLOCK, 3 ESCALATE)
