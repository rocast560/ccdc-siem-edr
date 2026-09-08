# Telemetry-only Defender sideload test (benign: real signed binaries, no proxy DLL)
New-Item -ItemType Directory -Force C:\Users\Public\DefCheck | Out-Null
Copy-Item 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Destination C:\Users\Public\DefCheck\
Copy-Item 'C:\Program Files\Windows Defender\mpclient.dll' -Destination C:\Users\Public\DefCheck\
Start-Process C:\Users\Public\DefCheck\MpCmdRun.exe -ArgumentList '-Scan','-ScanType','1' -WindowStyle Hidden
Write-Output 'MpCmdRun launched from C:\Users\Public\DefCheck'
