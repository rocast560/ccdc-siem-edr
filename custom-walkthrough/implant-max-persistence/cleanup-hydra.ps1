# HYDRA cleanup - removal order defeats the resurrection pair:
# WMI sub first (it re-arms the Run key), then the task, then everything else.
$ErrorActionPreference = "SilentlyContinue"
Write-Host "[1] re-armers first: WMI subscription..."
Get-WmiObject __EventFilter -Namespace root\subscription -Filter "Name='HydraFilter'" | Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter "Name='HydraConsumer'" | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription |
    Where-Object { $_.Filter -match 'Hydra' } | Remove-WmiObject
Write-Host "[2] then the task..."
schtasks /delete /f /tn "\Microsoft\Windows\CCDCTelemetry\Health" | Out-Null
Write-Host "[3] then the BITS job..."
bitsadmin /cancel HydraJob | Out-Null
Write-Host "[4] then the service..."
sc.exe stop SysHealthMon | Out-Null
sc.exe delete SysHealthMon | Out-Null
Write-Host "[5] then everything else..."
Remove-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name OneDriveSync
Remove-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name OneDriveSync
Remove-Item -Recurse "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}"
Remove-Item -Recurse "HKCU:\Software\Classes\ms-settings"
Remove-ItemProperty "HKCU:\Control Panel\Desktop" -Name SCRNSAVE.EXE
Remove-Item "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Netsh" -Name CCDCHelper
Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -Name CCDC
Remove-Item -Recurse "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\CCDCNtpClient"
Remove-Item -Recurse "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\CCDCMonitor"
Remove-Item -Recurse "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{CCDC-HYDRA}"
Remove-Item -Recurse "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\CCDCNotify"
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name Debugger
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\intel-update.bat"
Remove-Item -Recurse -Force C:\Users\Public\Intel
Remove-Item C:\Users\Public\readme.txt -Force   # also removes the ADS payload copy
Write-Host "[6] fresh baseline + clean-audit check..."
Invoke-RestMethod -Method Post "http://127.0.0.1:8420/api/baseline" | Out-Null
$audit = Invoke-RestMethod -Method Post "http://127.0.0.1:8420/api/audit"
if ($audit.findings.Count -eq 0) { Write-Host "CLEAN - hydra fully eradicated" }
else { Write-Host "RESIDUAL FINDINGS (check for re-arm!):"; $audit.findings }
