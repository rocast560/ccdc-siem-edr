# VICTIM - step 7 evasion variants. Run ONE at a time; .\victim-cleanup.ps1 between runs.
param(
    [string]$Kali = "172.16.69.109",
    [string]$Port = 8000,
    [ValidateSet("A","B","C")][Parameter(Mandatory=$true)][string]$Variant
)

switch ($Variant) {

"A" {
    Write-Host "== Variant A: Defender-host sideload (LockBit delivery style) =="
    Write-Host "   host: MpCmdRun.exe (Microsoft-signed)  proxy: mpclient.dll"
    Write-Host "   NOTE: real proxy mpclient.dll needs mpclient's full export set;"
    Write-Host "         telemetry-only variant below stages the GENUINE DLL - the launch"
    Write-Host "         from a non-default path is the anomaly the rule keys on."
    New-Item -ItemType Directory -Force C:\Users\Public\DefCheck | Out-Null
    Copy-Item 'C:\Program Files\Windows Defender\MpCmdRun.exe' -Destination C:\Users\Public\DefCheck\
    Copy-Item 'C:\Program Files\Windows Defender\mpclient.dll'  -Destination C:\Users\Public\DefCheck\
    Start-Process C:\Users\Public\DefCheck\MpCmdRun.exe -ArgumentList '-Scan','-ScanType','1' -WindowStyle Hidden
    Write-Host "   EXPECT: EVT-DEFENDER-SIDELOAD (critical) + EVT-4688-TEMP"
}

"B" {
    Write-Host "== Variant B: fake system-binary name =="
    if (-not (Test-Path C:\Users\Public\sysupd.exe)) {
        Copy-Item C:\Windows\System32\cmd.exe C:\Users\Public\sysupd.exe   # benign stand-in
    }
    Copy-Item C:\Users\Public\sysupd.exe C:\Users\Public\svchost.exe -Force
    Start-Process C:\Users\Public\svchost.exe -ArgumentList "/c","ping -n 25 127.0.0.1" -WindowStyle Hidden
    Write-Host "   EXPECT: EVT-4688-TEMP (path rule survives the rename); SIG rules unaffected"
}

"C" {
    Write-Host "== Variant C: deep innocuous path + timestamp spoof =="
    $deep = "C:\Users\Public\Intel\DriverStore"
    New-Item -ItemType Directory -Force $deep | Out-Null
    if (Test-Path C:\Users\Public\sysupd.exe) {
        Copy-Item C:\Users\Public\sysupd.exe "$deep\sysupd.exe"
    } else {
        Copy-Item C:\Windows\System32\cmd.exe "$deep\sysupd.exe"   # benign stand-in
    }
    (Get-Item "$deep\sysupd.exe").LastWriteTime = Get-Date "2020-01-01"
    (Get-Item "$deep\sysupd.exe").CreationTime = Get-Date "2020-01-01"
    Start-Process "$deep\sysupd.exe" -ArgumentList "/c","ping -n 25 127.0.0.1" -WindowStyle Hidden
    Write-Host "   EXPECT: EVT-4688-TEMP (still under \Users\Public\); timestomping itself = filed gap"
}
}
Write-Host "done - check the LIVE panel, then run .\victim-cleanup.ps1 before the next variant"
