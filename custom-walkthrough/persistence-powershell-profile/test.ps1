Write-Host "[1] writing PowerShell profile (expect PERS-PSPROFILE within 30s)..."
New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\WindowsPowerShell" | Out-Null
# marker-only line for the file-appearance test; for the full chain swap to:
#   Start-Process C:\Users\Public\sysupd.exe -WindowStyle Hidden
Set-Content "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" `
  "# ccdc persistence test marker"
Write-Host "[2] open a NEW PowerShell window - the profile runs in it"
Write-Host "cleanup: Remove-Item `$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
