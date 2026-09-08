# Cleanup for adv_persist_test.ps1 + stale run key
Remove-Item -Recurse -Force "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}" -ErrorAction SilentlyContinue
Remove-ItemProperty "HKCU:\Control Panel\Desktop" -Name SCRNSAVE.EXE -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "HKCU:\Software\Classes\ms-settings" -ErrorAction SilentlyContinue
Remove-Item C:\Users\Public\ccdc_stager_test.vbs -Force -ErrorAction SilentlyContinue
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name CCDCTestPayload -ErrorAction SilentlyContinue
Write-Output "registry/files cleaned"
