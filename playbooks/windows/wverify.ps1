# wverify.ps1 -- reports every Windows playbook artifact still present.
# Reads the ledger: anything listed AND still existing = not yet cleaned.
$Ledger = "$PSScriptRoot\..\ledger.jsonl"
if (-not (Test-Path $Ledger)) { Write-Host "no ledger - nothing planted from here"; exit 0 }
$dirty = 0
foreach ($line in (Get-Content $Ledger)) {
    try { $e = $line | ConvertFrom-Json } catch { continue }
    if ($e.playbook -notmatch "^ccdc-pb") { continue }
    $present = $false
    if ($e.artifact -like "HKCU:*" -or $e.artifact -like "HKLM:*") {
        $present = Test-Path $e.artifact
    } elseif ($e.artifact -like "\*") {          # scheduled task paths
        $present = [bool](Get-ScheduledTask -TaskName ($e.artifact -replace ".*\\") -ErrorAction SilentlyContinue)
    } elseif ($e.step -eq "wmi-sub") {
        $present = [bool](Get-WmiObject __EventFilter -Namespace root\subscription |
                          Where-Object { $_.Name -match "^_\{" })
    } elseif ($e.step -in ("dummy-service","svc-stop")) {
        $present = [bool](Get-Service CCDCSimSvc -ErrorAction SilentlyContinue)
    } else {
        $present = Test-Path $e.artifact
    }
    if ($present) {
        Write-Host ("  STILL PRESENT  [{0}] {1} -> {2}" -f $e.playbook, $e.step, $e.artifact)
        $dirty = 1
    }
}
# live implant processes
$procs = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match "sc_stage2|sleep_crypt|ccdc-pb3-loop|core\.exe.*EdgeUpdate" }
foreach ($p in $procs) {
    Write-Host ("  STILL RUNNING   pid {0}: {1}" -f $p.ProcessId, $p.CommandLine)
    $dirty = 1
}
if (-not $dirty) { Write-Host "== CLEAN: no playbook artifacts remain" } else { exit 1 }
