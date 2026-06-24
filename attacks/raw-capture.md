## T1059.001 — PowerShell (Execution)
- Test: #17 (PowerShell Command Execution)
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
