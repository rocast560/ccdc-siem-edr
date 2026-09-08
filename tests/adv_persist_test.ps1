# Benign artifacts for live-verifying the new persistence detections
# 1. COM hijack shadow (HKCU, safe; DLL need not exist for the diff)
New-Item -Path "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" -Name "(default)" -Value "C:\Users\Public\comhost.dll"
# 2. Screensaver hijack
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name SCRNSAVE.EXE -Value "C:\Users\Public\sysupd.exe"
# 3. PowerShell profile
New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\WindowsPowerShell" | Out-Null
Set-Content "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" -Value "# ccdc benign profile test"
# 4. BITS job
Import-Module BitsTransfer
Start-BitsTransfer -Source http://127.0.0.1:1/never.bin -Destination C:\Users\Public\nope.bin -AsJob -ErrorAction SilentlyContinue
# 5. fodhelper ms-settings proxy key
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\Users\Public\sysupd.exe"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name DelegateExecute -Value ""
# 6. script-host launcher (empty vbs)
Set-Content C:\Users\Public\ccdc_stager_test.vbs -Value "WScript.Quit"
Start-Process wscript.exe -ArgumentList "C:\Users\Public\ccdc_stager_test.vbs" -WindowStyle Hidden
Write-Output "artifacts planted"
