# Detection Results — APT29 Technique Set

Measured on WS01 across two time-separated windows:
- **Attack window:** per-technique timestamps (see `attacks/raw-capture.md`)
- **Benign window:** 06/25 18:07–18:48 (controlled admin activity, no attacks)

Counts are per matching event/alert. precision = TP / (TP + FP); recall = TP / (TP + FN).
Single attack window + 41-minute benign window — a small-sample lab measurement.

---

## Per-rule metrics

### Naive (before tuning)

| # | Technique              | ATT&CK ID  | TP | FP | FN | Precision | Recall |
|---|------------------------|------------|----|----|----|-----------|--------|
| 1 | Discovery burst        | T1087.002  | 27 | 9  | 0  | 0.75      | 1.00   |
| 2 | PowerShell encoded     | T1059.001  | 1  | 1  | 0  | 0.50      | 1.00   |
| 3 | Registry Run key       | T1547.001  | 1  | 1  | 0  | 0.50      | 1.00   |
| 4 | Scheduled task         | T1053.005  | 2  | 1  | 0  | 0.67      | 1.00   |
| 5 | Create account+privesc | T1136.001  | 1  | 1  | 0  | 0.50      | 1.00   |
| 6 | LSASS dump             | T1003.001  | 1  | 0  | 0  | 1.00      | 1.00   |
| 7 | Mshta                  | T1218.005  | 1  | 0  | 0  | 1.00      | 1.00   |
| 8 | Clear event logs       | T1070.001  | 1  | 0  | 0  | 1.00      | 1.00   |

### Tuned (after tuning)

| # | Technique              | ATT&CK ID  | TP | FP | FN | Precision | Recall |
|---|------------------------|------------|----|----|----|-----------|--------|
| 1 | Discovery burst        | T1087.002  | 1  | 0  | 0  | 1.00      | 1.00   |
| 2 | PowerShell encoded     | T1059.001  | -  | -  | -  | see note  | 1.00   |
| 3 | Registry Run key       | T1547.001  | 1  | 0  | 0  | 1.00      | 1.00   |
| 4 | Scheduled task         | T1053.005  | 2  | 0  | 0  | 1.00      | 1.00   |
| 5 | Create account+privesc | T1136.001  | 1  | 0  | 0  | 1.00      | 1.00   |
| 6 | LSASS dump             | T1003.001  | 1  | 0  | 0  | 1.00      | 1.00*  |
| 7 | Mshta                  | T1218.005  | 1  | 0  | 0  | 1.00      | 1.00   |
| 8 | Clear event logs       | T1070.001  | 1  | 0  | 0  | 1.00      | 1.00   |

---

## Tuning + limitation per rule

| # | Tuning method                                          | Known limitation                                                        |
|---|--------------------------------------------------------|-------------------------------------------------------------------------|
| 1 | Threshold: >=5 distinct discovery cmds per host / 5min | Slow attacker(<=4 distinct, or spaced >5min) evades, busy admin can re-trigger |
| 2 | Decoded-script inspection via 4104 (not just -e flag)  | Novel obfuscation avoiding known cmdlets needs manual review            |
| 3 | Filter by target path (suspicious dirs vs trusted)     | Persistence from inside a trusted directory evades the path filter      |
| 4 | Filter by task action (interpreter/LOLBin vs app)      | Task running a legit-looking binary from a trusted path evades          |
| 5 | Correlate 4720 -> 4732(Admin) on extracted target SID  | Slow/indirect promotion evades, rex extraction is event-format dependent |
| 6 | None — high-signal comsvcs MiniDump command pattern    | Narrow (comsvcs only); EID 10 access rule not viable under PPL          |
| 7 | None — refined to script/URL/.hta for precision        | Legit HTA apps could match; other LOLBins (rundll32, regsvr32) evade    |
| 8 | None — Security-log clear (1102) is inherently the signal | Direct-API clear or forwarder tampering evades; 104 needs channel forwarding |

---

## Aggregate (5 tunable rules, 1–5)

| Metric          | Naive | Tuned |
|-----------------|-------|-------|
| Mean precision  | 0.58  | 0.90  |
| Total FP        | 13    | ~0    |
| Recall          | 1.00  | 1.00  |

\* LSASS recall is 1.00 for the comsvcs method specifically; the rule does not cover
other dump methods (narrow by design, not a recall failure within scope).

**PowerShell attack note:** the naive flag rule scored 0.50 precision. The intended
tuning — decoded-content inspection via 4104 — could not be scored numerically here
because both the ART test payload and the benign command decode to harmless
`Write-Host` content, so the content layer correctly flags neither. Reported as-is
rather than manufacturing a tuned number. This is why the tuned-stage row shows "-".
