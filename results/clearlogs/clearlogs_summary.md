# Clear Event Logs — Detection Summary

**Technique:** T1070.001 (Defense Evasion)
**Rule:** detections/T1070.001_clear_logs.yaml

## Measurement (clean windows)
- Attack: 06/25 17:49 — wevtutil cl Security + cl System
- Benign: 06/25 18:07–18:48

| Metric                        | Rule (Security log cleared, 1102) |
|-------------------------------|-----------------------------------|
| True positive (attack caught) | Yes                               |
| False positives (benign)      | 0                                 |

## Why this is the highest-signal rule
Clearing the Security event log (1102) is almost never legitimate. FP-before = 0, no tuning needed — the event itself is the signal.

## Standout findings
1. Central SIEM defeats local anti-forensics: 1102 and all prior events remained in Splunk AFTER the local Security log was wiped, because they were forwarded before the clear. This is the core demonstration of why centralized logging exists.
2. Defense-in-depth detection — the same clear action was caught three independent ways:
   - Security EID 1102 (native "log cleared")
   - Sysmon EID 1 (wevtutil.exe process execution) — backstop
   - PowerShell EID 4104 (script block logged the wevtutil command)
3. Coverage lesson: the System-log clear (EID 104) was NOT seen because the System channel isn't forwarded — but Sysmon EID 1 still caught wevtutil clearing it. You natively detect only channels you collect; process-level telemetry backstops the gaps.

## Limitations (accepted blind spots)
- An attacker clearing logs via direct API (not wevtutil) evades the Sysmon wevtutil backstop, though 1102 still fires for the Security log.
- An attacker who stops/tampers the forwarder before clearing could prevent forwarding — mitigated by forwarder monitoring / heartbeat alerting (not implemented in this lab).
- 104 (System/Application clear) requires forwarding those channels to detect natively.