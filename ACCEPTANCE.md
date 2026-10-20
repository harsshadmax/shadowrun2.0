# Acceptance checklist (blueprint section 18, plus the four 2.0 security fixes)

Checked on the dev machine (Windows 11, WSL2 Ubuntu 24.04, Docker Engine 29.1.3, strace 6.13, Python 3.12.3).
Exact commands, exit codes and output: [`evidence/validation.log`](evidence/validation.log) (doctor 8/8 PASS,
235 tests passed, 3-repeat benchmark, audit chain OK).

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | `shadowrun doctor` passes all checks | PASS | 8/8 PASS (a new check proves the package cannot tamper with the trace); also run as the gate before every run (fail closed, tested) |
| 2 | Sandbox cannot reach the real internet | PASS | doctor check 3: `1.1.1.1` network unreachable, `example.com` does not resolve |
| 3 | strace logs a canary `openat` and an outbound `connect` | PASS | doctor check 5 and `tests/test_pipeline_e2e.py` |
| 4 | Sink stores sandbox traffic; no host port published | PASS | `docker port sink` prints nothing (`evidence/verify_demo_twice.txt`) |
| 5 | Hash mismatch rejected at install | PASS | `test_tampered_pin_is_rejected`: pip refuses, `HASH_MISMATCH`, BLOCK |
| 6 | No package code runs on the host | PASS (by construction) | fetch is HTTP + hashing; fixtures are assembled by `sdist_tool.py`, never built with `python -m build`. Not independently audited beyond that |
| 7 | Detector fires every rule on fixtures; pip baseline has zero findings | PASS | `tests/test_detector.py`, `tests/test_trace_completeness.py`; fixtures were recaptured through the new isolated tracer and give 0 findings |
| 8 | Strictest decision wins; errors fail closed | PASS | `tests/test_policy.py`; doctor-failure, unknown-package, parser-crash and failed-tracer e2e tests |
| 9 | 6 packages built with SIMULATED headers and plausible names | PASS | `tests/test_packages.py`, `packages/dist/INDEX.md` |
| 10 | M1 and M2 blocked with canary evidence; B1 to B3 allowed | PASS | e2e per manifest; benchmark matrix in the validation log |
| 11 | Time bomb slip reported honestly | PASS | M3 ALLOW in every run; stated in README, results notes and demo script |
| 12 | Agent is blocked, switches package, finishes | PASS | `test_agent_blocked_then_switches_and_finishes`, `evidence/demo_run.txt`, `eval/results/recorded_run.md` |
| 13 | Audit chain verifies and a tamper is detected | PASS | `tests/test_audit.py`; `audit verify` OK over 230 entries (`evidence/verify_demo_twice.txt`) |
| 14 | Dashboard works end to end; screens have loading/empty/error states | PASS | redesign driven in the in-app browser at 1440, 768 and 375 px (no horizontal scroll): scan dialog, window select, search, bell filter, tabs, row selection, Re-check, demo. 35 dashboard tests. The Docker-down error path was exercised only through tests, not in a browser |
| 15 | Templates are autoescaped (XSS test passes) | PASS | `test_untrusted_strings_are_escaped_everywhere`; no `innerHTML` and no inline handlers (tested) |
| 16 | Benchmark table has counts, false positives, latency and the disclaimer | PASS | `eval/results/results.md`, `latest.json`, `eval_results.csv` |
| 17 | Demo runs twice without manual database fixes | PASS | `scripts/verify_demo_twice.sh`: reset then record, twice, both exit 0 (`evidence/verify_demo_twice.txt`) |
| 18 | **Fix 1:** one honest, consistent health status | PASS | `tests/test_health.py` (14), 9 dashboard consistency tests: PASS/FAIL/STALE/UNKNOWN, per-run doctor id, no doctor check during a scan, pill and panel converge. The original screenshot mismatch was not reproduced; causes found by code reading |
| 19 | **Fix 2:** the package cannot alter the trace evidence | PASS | `tests/test_evidence_isolation.py` (23): 10 tampering attempts denied, hostile wipe-your-own-trace package still BLOCKED with intact trace, ownership/mode/hash checks |
| 20 | **Fix 3:** downloads only from the intended registry | PASS | `tests/test_fetcher.py` (68): allowlist, lookalike hosts, credentials, alternate IP spellings, hostile links and redirects, private/loopback resolution, DNS rebinding pinned to one IP |
| 21 | **Fix 4:** missing or unparsed evidence is uncertainty | PASS | `tests/test_trace_completeness.py` (17) and e2e: empty, malformed, truncated, unresumed, cut-off strings, missing pip exec, failed tracer, parser crash all give a denied, indeterminate verdict |

Targeted regression run for the four fixes: [`evidence/regression_four_fixes.txt`](evidence/regression_four_fixes.txt).
Fresh demo with consistent status: [`evidence/demo_status.txt`](evidence/demo_status.txt) and
[`evidence/split_screen_demo.gif`](evidence/split_screen_demo.gif) (replay assembled from real captures).

## Known gaps

- M3 time bomb is a missed attack (needs a clock-shifting deep mode).
- No real-install step, approval UI, MODIFY, cache or npm support (roadmap).
- Latency shows container start and install as one `sandbox` measurement. Median decision rose from 2.6 s to 3.1 s
  with the evidence isolation; the extra time was not profiled.
- The benchmark is 6 simulated packages, 3 repeats. It demonstrates the mechanism, not real-world detection rates.
- The split-screen "recording" is a replay assembled from real screenshots and terminal output, not a live screen
  capture; no screen recorder (ffmpeg, OBS, Chrome) was available.
- The allowlist governs the fetcher. The doctor's registry probe and the agent talk to fixed localhost constants.
- The strace syscall list adds `chdir`, `clone`, `clone3`, `fork`, `vfork`; `AF_UNIX` connects are parsed but not
  flagged; symlinks are not resolved; traces over 32 MB are refused (indeterminate verdict).
