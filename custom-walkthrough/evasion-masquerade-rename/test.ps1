if (-not (Test-Path C:\Users\Public\sysupd.exe)) {
    Copy-Item C:\Windows\System32\cmd.exe C:\Users\Public\sysupd.exe   # benign stand-in
}
Write-Host "[1] renaming to a system-binary name (expect EVT-4688-TEMP + PROC-MASQ)..."
Copy-Item C:\Users\Public\sysupd.exe C:\Users\Public\svchost.exe -Force
Write-Host "[2] launching the fake svchost (kept alive 25s)..."
Start-Process C:\Users\Public\svchost.exe -ArgumentList "/c","ping -n 25 127.0.0.1" -WindowStyle Hidden
Write-Host "every expected rule is path/byte based - the rename must NOT evade"
