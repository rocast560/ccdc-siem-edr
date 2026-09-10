# wcleanup.ps1 -- removes every artifact planted by the Windows playbooks,
# reading ground truth from ledger.jsonl plus the known fixed locations.
#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"
$Ledger = "$PSScriptRoot\..\ledger.jsonl"
$found = @()

# processes first (implants + loops)
Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match "sc_stage2|sleep_crypt|ccdc-pb3-loop|ccdc-simsvc|core\.exe.*EdgeUpdate"
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; $found += "pid $($_.ProcessId)" }

# tasks
foreach ($t in ("CCDCSimWatch", (Get-ScheduledTask | Where-Object {
        $_.TaskName -match "MicrosoftEdgeUpdateCore_|DsmUserTask_"
    }).TaskName)) {
    if ($t) { Unregister-ScheduledTask -TaskName $t -Confirm:$false; $found += "task $t" }
}

# WMI subscriptions
Get-WmiObject __EventFilter -Namespace root\subscription | Where-Object {
    $_.Name -match "^_\{" } | Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription | Where-Object {
    $_.Name -match "^_\{" } | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Remove-WmiObject

# registry (from ledger only — never wildcard user COM classes)
foreach ($line in (Get-Content $Ledger -ErrorAction SilentlyContinue)) {
    try { $e = $line | ConvertFrom-Json } catch { continue }
    if ($e.artifact -like "HKCU:*" -or $e.artifact -like "HKLM:*") {
        Remove-Item -Recurse -Force $e.artifact; $found += $e.artifact
    }
}

# files + dummy service
foreach ($p in ("$env:LOCALAPPDATA\Microsoft\EdgeUpdate",
                "$env:PROGRAMDATA\Microsoft\Crypto\Keys",
                "$env:ProgramData\ccdc-pb3-loop.ps1",
                "$env:ProgramData\ccdc-simsvc.exe",
                "$env:TEMP\sc_stage2.py")) {
    if (Test-Path $p) { Remove-Item -Recurse -Force $p; $found += $p }
}
sc.exe stop CCDCSimSvc | Out-Null
sc.exe delete CCDCSimSvc | Out-Null

Write-Host "== wcleanup removed:"; $found | ForEach-Object { Write-Host "   $_" }
Write-Host "== run .\wverify.ps1 to prove it"
