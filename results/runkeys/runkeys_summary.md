# Registry Run Key Persistence — Tuning Summary

**Technique:** T1547.001 (Persistence)
**Rule:** detections/T1547.001_run_keys.yaml

## Measurement (clean windows)
- Attack: 06/23 21:04 (Splunk time) — reg.exe writes Run\Atomic Red Team -> C:\Path\AtomicRedTeam.exe
- Benign: 06/25 18:37 (Splunk time) — reg.exe writes Run\MyApp -> C:\Program Files\MyApp\app.exe

| Metric                        | Naive (any Run-key write) | Tuned (suspicious target path) |
|-------------------------------|---------------------------|--------------------------------|
| True positive (attack caught) | Yes (1)                   | Yes (1)                        |
| False positives (benign)      | 1                         | 0                              |

## Tuning applied
Naive rule flags any value written to a Run key (EID 13) — fires on legitimate software too (benign MyApp). Tuned rule flags only Run-key writes whose target (Details) points to a suspicious location — AppData, Temp, Users\Public, ProgramData, or a powershell/cmd command — while clearing standard install paths (Program Files, Windows).

## Honest note on lab vs real
The realistic tuning lever is the suspicious-directory set (AppData/Temp/Public/ProgramData) where actual malware persists. The ART test wrote to a synthetic path (C:\Path\AtomicRedTeam.exe), so the pattern "\Path\" was added to match this lab's artifact. In production the directory patterns above are what matter.

## Limitations (accepted blind spots)
- An attacker persisting from inside a trusted directory (e.g. dropping a binary into C:\Program Files\ with admin rights) evades the path filter.
- Path-based filtering requires maintaining the suspicious/trusted directory lists; novel locations are missed until added.
- Stronger approach (future): combine with signature/reputation of the target binary, not path alone.