Write-Host "[1] simulating the PsExec destination half (expect EVT-7045 + PERS-SERVICE)..."
if (Test-Path C:\Users\Public\sysupd.exe) { Copy-Item C:\Users\Public\sysupd.exe C:\Windows\System32\PSEXESVC.exe -Force }
else { Copy-Item C:\Windows\System32\cmd.exe C:\Windows\System32\PSEXESVC.exe -Force }
sc.exe create PSEXESVC binPath= "C:\Windows\System32\PSEXESVC.exe" displayname= "PSEXESVC" | Out-Null
sc.exe start PSEXESVC | Out-Null
Write-Host "5145 ADMIN$ write detection = filed gap (channel not consumed yet)"
Write-Host "cleanup: sc delete PSEXESVC; Remove-Item C:\Windows\System32\PSEXESVC.exe"
