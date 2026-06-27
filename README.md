# APT29 Detection Engineering — Splunk + Sigma Home Lab

A detection-engineering project covering the full lifecycle for 8 APT29 techniques:
run the technique, capture the telemetry, write a Sigma rule, convert it to Splunk,
prove it fires, measure false positives against normal admin activity, and tune it.

Scope is a single Windows workstation. Detections were measured against both an
attack window and a controlled benign window so the false-positive numbers are real,
not assumed.

---

## Lab

```
[ WS01 - Windows 11 victim ]            [ Ubuntu - Splunk ]
  Sysmon (SwiftOnSecurity cfg,            index=main
    LSASS ProcessAccess enabled)          receives :9997
  PowerShell Script Block Logging
        |
        |  Universal Forwarder ships 3 channels:
        |    WinEventLog:Security
        |    WinEventLog:Microsoft-Windows-Sysmon/Operational
        |    WinEventLog:Microsoft-Windows-PowerShell/Operational
        +------------------------------------------------> Splunk
```

Attacks are run on WS01 with Atomic Red Team. A separate block of normal admin
activity (the benign window) provides the false-positive baseline.

---

## Repo layout

```
apt29-detection-lab/
├── README.md
├── detections/
│   ├── T1059.001_powershell_encoded.yaml
│   ├── T1547.001_run_keys.yaml
│   ├── T1053.005_scheduled_task.yaml
│   ├── T1087_discovery.yaml
│   ├── T1136.001_create_account.yaml
│   ├── T1003.001_lsass.yaml
│   ├── T1218.005_mshta.yaml
│   ├── T1070.001_clear_logs.yaml
│   └── splunk_winevent_pipeline.yml      # custom pySigma pipeline (EventID -> EventCode)
├── attacks/
│   └── raw-capture.md                    # per-technique notes: what each attack left behind
└── results/
    ├── results_table.md                  # full metrics table
    ├── discovery/                        # screenshots + summary.md  (one folder per technique)
    ├── powershell/
    ├── runkeys/
    ├── schtask/
    ├── account/
    ├── lsass/
    ├── mshta/
    └── clearlogs/
```

---

## How a detection is built (the loop)

Every rule went through the same loop. Using T1059.001 (encoded PowerShell) as the example:

**1. Run the technique on WS01**
```
Invoke-AtomicTest T1059.001 -TestNumbers 17
```

**2. Confirm the raw telemetry in Splunk**
```
index=main host=WS01 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=1 Image="*powershell*" CommandLine="* -e *"
```

**3. Write the Sigma rule** (`detections/T1059.001_powershell_encoded.yaml`)
```yaml
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\powershell.exe'
  selection_flag:
    CommandLine|contains: [' -e ', ' -enc', ' -EncodedCommand']
  condition: selection_img and selection_flag
```

**4. Convert Sigma -> Splunk with pySigma**
```
sigma convert -t splunk -p sysmon -p detections/splunk_winevent_pipeline.yml \
  detections/T1059.001_powershell_encoded.yaml
```
The sysmon pipeline maps Sigma's generic field names; the custom
`splunk_winevent_pipeline.yml` rewrites `EventID` to `EventCode`, because the
forwarded Windows logs use `EventCode`. Without it the rules convert cleanly but
return zero hits. Security-log rules (4698/4720/1102) convert with only the custom
pipeline, not the sysmon one.

**5. Confirm the generated search returns the attack event.** Index and sourcetype
are added per deployment (Sigma stays environment-agnostic).

---

## Measurement method

For each rule, in a defined window:
- **TP** — fired on the real attack
- **FP** — fired on benign activity
- **FN** — real attack instances missed
- **precision = TP / (TP + FP)**, **recall = TP / (TP + FN)**

Measured twice per rule: naive (before tuning) and tuned (after). Windows:
- Attack: per-technique timestamps in `attacks/raw-capture.md`
- Benign: 06/25 18:07–18:48 (controlled admin activity, no attacks)

Metrics come from one attack window and one 41-minute benign window — a small-sample
lab measurement that demonstrates the tuning effect, not a production benchmark.

---

## Results

| # | Technique             | ATT&CK ID  | FP before | FP after | Precision (naive -> tuned) | Recall | Tuning method                                    |
|---|-----------------------|------------|-----------|----------|----------------------------|--------|--------------------------------------------------|
| 1 | Discovery burst       | T1087.002  | 9         | 0        | 0.75 -> ~1.0               | 1.00   | Threshold: >=5 distinct discovery cmds / 5 min   |
| 2 | PowerShell encoded    | T1059.001  | 1         | see note | 0.50 (see note)            | 1.00   | Decoded-script inspection via 4104               |
| 3 | Registry Run key      | T1547.001  | 1         | 0        | 0.50 -> 1.0                | 1.00   | Filter by target path (suspicious vs trusted)    |
| 4 | Scheduled task        | T1053.005  | 1         | 0        | 0.67 -> 1.0                | 1.00   | Filter by task action (interpreter/LOLBin)       |
| 5 | Create account+privesc| T1136.001  | 1         | 0        | 0.50 -> 1.0                | 1.00   | Correlate 4720 -> 4732(Admin) on target SID      |
| 6 | LSASS dump            | T1003.001  | 0         | 0        | 1.0                        | 1.00*  | None — high-signal comsvcs MiniDump pattern      |
| 7 | Mshta                 | T1218.005  | 0         | 0        | 1.0                        | 1.00   | None — refined to script/URL/.hta for precision  |
| 8 | Clear event logs      | T1070.001  | 0         | 0        | 1.0                        | 1.00   | None — Security-log clear (1102) is the signal   |

Across the five tunable rules (1–5): mean precision **0.58 -> 0.90**, false positives
**13 -> ~0**, recall held at **1.00** (no attack missed).

\* LSASS recall is 1.00 for the comsvcs method; the rule is narrow by design and does
not cover other dump methods.

**PowerShell note:** the naive flag rule scored precision 0.50 (it fired on one benign
encoded command). The tuning is content inspection of the decoded script via 4104. In
this lab both the attack test payload and the benign command decode to harmless
`Write-Host`, so the content layer flags neither — no honest numeric gain can be
claimed, so the rule is reported as-is. In a real intrusion where the payload decodes
to a download cradle, the content layer flags the attack and clears the benign command.

---

## Findings

**1. Tuning is not one-size-fits-all.** Five rules fired on legitimate activity and
each needed a different method: a behavioral threshold, decoded-content inspection,
path filtering, action filtering, and event-sequence correlation. Three rules were
high-signal by nature — for those the right call was to measure and confirm precision,
then leave them alone rather than invent a reduction the data wouldn't support.

**2. `net` runs as `net1` in telemetry.** `net group` / `net user` execute internally
as `net1.exe`. A rule matching only `net ` misses half the discovery activity; the
match strings were corrected to catch both.

**3. PPL changes the LSASS detection.** With `RunAsPPL=2`, every dump tool was denied
at the kernel before opening a read handle, so Sysmon EID 10 logged no malicious
access. The viable detection is the command pattern (EID 1, `comsvcs.dll MiniDump`),
which catches the attempt whether or not the dump succeeds. The access-mask rule would
be the stronger, method-agnostic detection on a host without PPL.

**4. Multi-value SID breaks naive correlation.** Correlating account-created ->
promoted-to-admin failed because `Security_ID` carries both the actor and the target,
and the actor SID is in every event. The fix was extracting the target SID
specifically (`rex` on the New Account / Member section) and correlating on that —
which is also the production approach, since it needs no admin-SID allowlist.

**5. A central SIEM defeats local log-clearing.** After the Security log was cleared
on the host, the 1102 event and all prior events were still in Splunk (already
forwarded). The same clear was caught three ways: native 1102, Sysmon process
creation of `wevtutil`, and PowerShell 4104.

**6. Validate the field mapping before scaling.** The forwarded Windows logs use
`EventCode`, not `EventID`. Rules converted cleanly but returned zero hits until the
custom pipeline rewrote the field — caught on rule one, before writing the other seven.
