# VICTIM - Phase 8: full cleanup of every artifact this runbook's tests create,
# then a fresh persistence baseline. Run elevated when the test session is over.
$ErrorActionPreference = "SilentlyContinue"

# processes
Stop-Process -Name sysupd, sysupd2, imix, imix_http, imix_stripped -Force

# service (5.1)
sc.exe stop CCDCTestSvc | Out-Null; sc.exe delete CCDCTestSvc | Out-Null

# scheduled task (5.2)
schtasks /delete /f /tn "CCDCTestTask" | Out-Null

# run key (5.3) + startup (5.4)
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "CCDCTestPayload"
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ccdc-test-persistence.bat"

# WMI subscription (5.5)
Get-WmiObject __EventFilter -Namespace root\subscription -Filter "Name='CCDCImixFilter'" | Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter "Name='CCDCImixConsumer'" | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription |
    Where-Object { $_.Filter -match 'CCDCImix' } | Remove-WmiObject

# advanced persistence (5.7-5.10, 6.8)
Remove-Item -Recurse -Force "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}"
Remove-ItemProperty "HKCU:\Control Panel\Desktop" -Name SCRNSAVE.EXE
Remove-Item "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
bitsadmin /cancel CCDCTestJob2 | Out-Null
Remove-Item -Recurse -Force "HKCU:\Software\Classes\ms-settings"

# files
Remove-Item "$env:TEMP\sysupd.exe", "$env:TEMP\sysupd_stripped.exe" -Force
Remove-Item C:\Users\Public\sysupd.exe, C:\Users\Public\sysupd2.exe, C:\Users\Public\svchost.exe,
            C:\Users\Public\ccdc_stager_test.vbs, C:\Users\Public\sideload_proof.txt,
            C:\Users\Public\comhost.dll, C:\Users\Public\update.dll -Force
Remove-Item -Recurse -Force C:\Users\Public\DefCheck, C:\Users\Public\SigCheck

# defender exclusions (6.3)
Remove-MpPreference -ExclusionPath C:\Users\Public

Write-Host "cleanup done. taking fresh EDR baseline..."
Invoke-RestMethod -Method Post "http://127.0.0.1:8420/api/baseline" | Out-Null
$audit = Invoke-RestMethod -Method Post "http://127.0.0.1:8420/api/audit"
if ($audit.findings.Count -eq 0) { Write-Host "clean: no residual findings" }
else { Write-Host "residual findings - check manually:"; $audit.findings }
