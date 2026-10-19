# Recorded demo run (2026-10-19T20:40:56+00:00)

_SIMULATED scenario: simulated agent, simulated package, fake secrets, sink inside the sandbox network._

Task: **Add CSV export to the report module.**

## Without Shadow-Run

Leaked canary tokens reaching the sink: **1** (CANARY-71f0493cef49-ssh)

## With Shadow-Run

- `report-export-pro`: **BLOCK** in 3.2s. Blocked. CANARY_EXFIL: Canary secret reached the sink (CANARY-54ff9ca6c4d7-ssh); CANARY_READ: Package code opened canary file /home/sandbox/.ssh/id_rsa; NET_OUTBOUND: Outbound connect to 172.18.0.2:9000 during an offline install
  - critical CANARY_EXFIL: Canary secret reached the sink (CANARY-54ff9ca6c4d7-ssh)
  - high CANARY_READ: Package code opened canary file /home/sandbox/.ssh/id_rsa
  - high NET_OUTBOUND: Outbound connect to 172.18.0.2:9000 during an offline install
- `csvtoolkit`: **ALLOW** in 2.9s. No suspicious behaviour in the tested run (limited evidence).

## Agent transcript (SIMULATED AGENT)

1. `PROPOSE` Task: Add CSV export to the report module. I will use `report-export-pro` for the CSV export.
2. `BLOCKED_NOTICE` `report-export-pro` was blocked by Shadow-Run: Blocked. CANARY_EXFIL: Canary secret reached the sink (CANARY-54ff9ca6c4d7-ssh); CANARY_READ: Package code opened canary file /home/sandbox/.ssh/id_rsa; NET_OUTBOUND: Outbound connect to 172.18.0.2:9000 during an offline install
3. `CHOOSE_ALT` Using `csvtoolkit` instead.
4. `CONTINUE` `csvtoolkit` allowed (limited evidence). Wrote /home/harsshad/shadow-run/.data/agent_workspace/report_export.py; task complete.
