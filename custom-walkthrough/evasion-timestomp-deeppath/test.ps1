if (-not (Test-Path C:\Users\Public\sysupd.exe)) {
    Copy-Item C:\Windows\System32\cmd.exe C:\Users\Public\sysupd.exe   # benign stand-in
}
$deep = "C:\Users\Public\Intel\DriverStore"
Write-Host "[1] planting at a deep innocuous path..."
New-Item -ItemType Directory -Force $deep | Out-Null
Copy-Item C:\Users\Public\sysupd.exe "$deep\sysupd.exe" -Force
Write-Host "[2] backdating timestamps (the timestomp - currently a filed gap)..."
(Get-Item "$deep\sysupd.exe").LastWriteTime = Get-Date "2020-01-01"
(Get-Item "$deep\sysupd.exe").CreationTime = Get-Date "2020-01-01"
Write-Host "[3] launching (expect EVT-4688-TEMP - the path rule is depth-blind)..."
Start-Process "$deep\sysupd.exe" -ArgumentList "/c","ping -n 25 127.0.0.1" -WindowStyle Hidden
Write-Host "cleanup: Remove-Item -Recurse C:\Users\Public\Intel"
