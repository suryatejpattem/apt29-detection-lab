## T1059.001 — PowerShell (Execution)
- Test: #17 
- Command: cmd.exe /c powershell.exe -e <base64> (decodes to Write-Host hello)
- Time run: 06/23/2026 04:26:41.230 PM
- Telemetry seen:
  - Sysmon EID 1: CommandLine had "-e <base64>", Parent cmd.exe -> powershell.exe
  - PowerShell EID 4104: logged 4 script blocks. Key one = decoded payload "Write-Host 'Hello, from PowerShell!'"; also captured the    OBFUSCATED form (string-concat + gcm) showing why literal-match detection fails. Confirms 4104 reveals intent that EID 1's base64 hides.
- Status: confirmed in Splunk (EID 1 ✓, 4104 ✓)


## T1547.001 — Registry Run Keys (Persistence)
- Test: #1
- Action: writes a value under HKCU\...\CurrentVersion\Run (auto-runs at login)
- Time run: 06/23/2026 06:04:02.849 PM
- Telemetry seen: Sysmon EID 13 (registry value set); TargetObject = ...\Run\..., Image = writing process, Details = value data
- Durable artifact: the Run-key write itself (EID 13), regardless of tool
- Notes: detect by effect (EID 13) not tool (reg.exe). Phase 5: widen to RunOnce/HKLM/autostart family; flag hive for severity.
- Status: confirmed in Splunk (EID 13 ✓)

## T1053.005 — Scheduled Task (Persistence/Execution)
- Test: #1
- Action: registers a scheduled task via schtasks.exe with Task Scheduler
- Time run: 06/25/2026 07:14:22.769 AM
- Telemetry seen: "4698 empty - auditing off; saw schtasks via Sysmon EID 1; enabled 'Other Object Access Events' then 4698 appeared"
- Durable artifact: task creation event (Security 4698), regardless of tool
- Notes: 4698 needs "Other Object Access Events" auditing. Record whether it was on by default or had to be enabled.
- Status: confirmed in Splunk (EID 1 ✓, 4698✓) 

## T1033/T1016/T1018/T1082/T1087.002/T1069.002 — Discovery (Account/System/Network/Permission) (Discovery)
- Test: T1033-1, T1016-1, T1018-1, T1082-1, T1087.002-1, T1069.002-1 (run as one burst)
- Action: built-in read-only commands (whoami, ipconfig/arp, net view, systeminfo, net user/group /domain, net localgroup) to map identity, network, system, and accounts
- Time run: 06/25/2026 08:42:51.743 AM
- Telemetry seen: Sysmon EID 1 (process creation), 11 distinct discovery commands in one 5-min window; behavioral query distinct_cmds=11 (threshold 4) fired; naive query = per-command FP baseline
- Durable artifact: NOT a single command — the behavioral burst (>=4 distinct discovery commands per host in 5 min)
- Notes: domain sub-commands (T1087.002, T1069.002) RPC-failed (analyst=local, no domain rights) but still generated EID 1 events — detection fires on execution, not success. wmic sub-commands errored (removed in Win11), harmless. T1087.001 & T1069.001 had no Windows tests, excluded. User field shows NOT_TRANSLATED (Sysmon user-field parsing; Splunk Sysmon Add-on fixes it; non-blocking).
- Status: confirmed in Splunk (EID 1 ✓, behavioral rule ✓)
