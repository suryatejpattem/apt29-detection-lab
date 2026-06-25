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

## T1003.001 — LSASS Memory (Credential Access)
- Test: #2 (Dump LSASS via comsvcs.dll MiniDump)
- Action: rundll32.exe calls comsvcs.dll MiniDump on lsass PID to dump its memory to a .dmp file
- Time run: 06/25/2026 01:23:26.586 PM
- Telemetry seen: Sysmon EID 1 (process creation) — rundll32.exe with CommandLine "comsvcs.dll MiniDump <lsass-pid> ...lsass-comsvcs.dmp full". EID 10 did NOT fire: PPL (RunAsPPL=2) blocked the memory access before a handle was opened, so no successful ProcessAccess was logged.
- Durable artifact: comsvcs MiniDump command pattern (EID 1: comsvcs + MiniDump) — catches the attempt even when PPL blocks the access; complement with EID 10 read-access for non-PPL-blocked methods
- Notes: EID 1 catches the tool execution (attempt); EID 10 catches successful memory read. PPL blocked the read, so only EID 1 fired — defense-in-depth working, detection still fires on the attempt. comsvcs+MiniDump is high-signal (almost nothing benign runs it).
- Status: confirmed in Splunk (EID 1 ✓)

## T1136.001 — Create Local Account (Persistence)
- Test: #4 (create user via cmd) + #8 (create admin user)
- Action: creates local backdoor accounts; test 8 also adds the account to Administrators
- Time run: 06/25/2026 01:56:29.464 PM, 06/25/2026 01:56:47.644 PM
- Telemetry seen: Security EID 4720 (accounts created: backdoor_svc, <test8 name>); EID 4732 (test 8 account added to Administrators)
- Durable artifact: account creation (4720), regardless of tool; strongest signal = 4720 followed by 4732 within seconds (fresh account given admin)
- Notes: ART tests start at #4 (1-3 non-Windows). Test 4 needed a complexity-compliant password (-InputArgs) because the domain password policy (GPO) rejected the weak default - incidental confirmation the domain enforces policy. High-signal, low-FP technique; 4720->4732 sequence = key attacker pattern.
- Status: confirmed in Splunk (4720 ✓, 4732 ✓)

## T1218.005 — Mshta (Defense Evasion / LOLBin)
- Test: #2 (Mshta executes inline VBScript)
- Action: mshta.exe runs inline VBScript — trusted signed Windows binary used to execute attacker script (LOLBin)
- Time run: 06/25/2026 02:26:42.906 PM
- Telemetry seen: Sysmon EID 1 — Image=mshta.exe, ParentImage=cmd.exe, CommandLine = mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ...powershell.ps1...")
- Durable artifact: mshta.exe execution with inline script / URL / .hta in CommandLine (EID 1)
- Notes: high-signal, low-FP — mshta rarely runs benignly on a workstation. Stronger with ParentImage context (Office/script launching mshta = very suspicious).
- Status: confirmed in Splunk (EID 1 ✓)

## T1070.001 — Clear Windows Event Logs (Defense Evasion)
- Test: ran directly (ART had no Windows yaml for T1070.001 in this pull)
- Action: wevtutil cl System + wevtutil cl Security — clears event logs (anti-forensics)
- Time run: 06/25/2026 02:49:16.474 PM
- Telemetry seen (3 layers):
  - Security EID 1102 (Security log cleared) — native, high-signal ✓
  - Sysmon EID 1 — wevtutil.exe cl System/Security (process execution) ✓ — backstop
  - PowerShell EID 4104 — script block logged the wevtutil command ✓
  - EID 104 (System log cleared) NOT seen — System channel not forwarded (inputs.conf only has Security/Sysmon/PowerShell)
- Durable artifact: 1102 (Security clear) primary; wevtutil execution via Sysmon EID 1 as backstop for logs not natively collected
- Notes: HIGHEST-signal native detection (1102, near-zero FP). KEY: 1102 + all prior events survived in Splunk after local wipe — central SIEM defeats log-clearing. Defense-in-depth: caught the same action 3 ways; System-log clear (104) wasn't forwarded but Sysmon EID 1 still caught wevtutil running. Coverage lesson: you only detect channels you collect.
- Status: confirmed in Splunk (1102 ✓, Sysmon EID 1 ✓, 4104 ✓; 104 N/A - channel not forwarded)