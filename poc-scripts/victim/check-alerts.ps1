# VICTIM - Phase 7 scoreboard: tally alerts by rule against the expected coverage table.
param([string]$Edr = "http://127.0.0.1:8420")

$s = Invoke-RestMethod "$Edr/api/state"
$groups = $s.alerts | Group-Object rule | Sort-Object Name
Write-Host ("uptime {0:n0}s | events {1:n0} | alerts {2:n0}" -f ((Get-Date) - $s.stats.started).TotalSeconds, $s.stats.events_total, $s.stats.alerts_total)
Write-Host ""
$groups | ForEach-Object { Write-Host ("{0,4}  {1}" -f $_.Count, $_.Name) }

$expected = "SIG-REALM-IMIX","SIG-RUST-IMPLANT","PROC-ENC-PS","EVT-4688-SUSP","EVT-4688-TEMP",
            "PROG-IMPLANT-LAUNCH","NET-BEACON","PERS-RUNKEY","PERS-SERVICE","EVT-7045","PERS-TASK",
            "EVT-4698","PERS-STARTUP","PERS-WMI-SUB","PERS-COM","PERS-SCREENSAVER","PERS-PSPROFILE",
            "PERS-BITS","PERS-UAC-KEY","TAMPER-AUDIT","TAMPER-DEFENDER","EVT-SCRIPTHOST",
            "EVT-DEFENDER-SIDELOAD"
$seen = $s.alerts.rule | Select-Object -Unique
Write-Host ""
$missing = $expected | Where-Object { $_ -notin $seen }
if ($missing) { Write-Host "NOT YET SEEN (run the matching test, or file as gap):"; $missing }
else { Write-Host "full coverage: every expected rule fired at least once" }
