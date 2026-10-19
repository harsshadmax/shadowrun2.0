# Acceptance checklist (blueprint section 18)

Checked on the dev machine (Windows 11, WSL2 Ubuntu, Docker Engine 29.1.3) with 92 passing tests, `shadowrun doctor`
ALL PASS, a 3-repeat benchmark (`eval/results/results.md`) and two consecutive recorded demo runs.

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | `shadowrun doctor` passes all checks | PASS | 7/7 PASS, also run before every pipeline run (fail closed, tested) |
| 2 | Sandbox cannot reach the real internet | PASS | doctor check 3: `1.1.1.1` network unreachable, `example.com` does not resolve |
| 3 | strace logs a canary `openat` and an outbound `connect` | PASS | doctor check 5 and `tests/test_pipeline_e2e.py` |
| 4 | Sink stores sandbox traffic; no host port published | PASS | `docker port sink` prints nothing; sink log read from the mounted `.data/sink` |
| 5 | Hash mismatch rejected at install | PASS | `test_tampered_pin_is_rejected`: pip refuses, `HASH_MISMATCH`, BLOCK |
| 6 | No package code runs on the host | PASS (by construction) | fetch is HTTP + hashing; fixtures are assembled by `sdist_tool.py`, never built with `python -m build`; `build_all.py` runs no package code. Not independently audited beyond that |
| 7 | Detector fires every rule on fixtures; pip baseline has zero findings | PASS | `tests/test_detector.py` covers all nine rules; real wheel and sdist traces give 0 findings |
| 8 | Strictest decision wins; errors fail closed | PASS | `tests/test_policy.py`, doctor-failure and unknown-package e2e tests |
| 9 | 6 packages built with SIMULATED headers and plausible names | PASS | `tests/test_packages.py`, `packages/dist/INDEX.md` |
| 10 | M1 and M2 blocked with canary evidence; B1 to B3 allowed | PASS | e2e per manifest; benchmark matrix |
| 11 | Time bomb slip reported honestly | PASS | M3 ALLOW in every run; stated in README, results notes and demo script |
| 12 | Agent is blocked, switches package, finishes | PASS | `test_agent_blocked_then_switches_and_finishes`, `recorded_run.md` |
| 13 | Audit chain verifies and a tamper is detected | PASS | `tests/test_audit.py` (payload edit, middle-row delete); `audit verify` OK over 194 entries |
| 14 | Dashboard works end to end; screens have loading/empty/error states | PASS | driven in the in-app browser: demo, Live Gate, Verify chain, 375px width with no horizontal scroll. Error and empty states are asserted in tests but the Docker-down error path was not exercised in a browser |
| 15 | Templates are autoescaped (XSS test passes) | PASS | `test_runs_fragment_escapes_untrusted_strings`, no `innerHTML` in `app.js` (tested) |
| 16 | Benchmark table has counts, false positives, latency and the disclaimer | PASS | `eval/results/results.md`, `latest.json`, `eval_results.csv` |
| 17 | Demo runs twice without manual database fixes | PASS | `scripts/verify_demo_twice.sh`: reset then record, twice, both exit 0 |

## Known gaps (also in README)

- M3 time bomb is a missed attack (needs a clock-shifting deep mode).
- No real-install step, approval UI, MODIFY, cache or npm support (roadmap).
- Latency shows container start and install as one `sandbox` measurement.
- The benchmark is 6 simulated packages, 3 repeats. It demonstrates the mechanism, not real-world detection rates.
