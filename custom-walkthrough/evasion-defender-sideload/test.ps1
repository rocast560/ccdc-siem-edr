Write-Host "[1] staging signed Defender binaries to a user folder (telemetry-only variant)..."
New-Item -ItemType Directory -Force C:\Users\Public\DefCheck | Out-Null
Copy-Item 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Destination C:\Users\Public\DefCheck\
Copy-Item 'C:\Program Files\Windows Defender\mpclient.dll'  -Destination C:\Users\Public\DefCheck\
Write-Host "[2] running MpCmdRun from the user path (expect EVT-DEFENDER-SIDELOAD)..."
Start-Process C:\Users\Public\DefCheck\MpCmdRun.exe -ArgumentList '-Scan','-ScanType','1' -WindowStyle Hidden
Write-Host "cleanup: Remove-Item -Recurse C:\Users\Public\DefCheck"
