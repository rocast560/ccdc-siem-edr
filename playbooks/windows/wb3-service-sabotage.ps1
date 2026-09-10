# wb3-service-sabotage.ps1 -- INTERVAL SERVICE-SABOTAGE playbook (Windows)
# Creates a DUMMY service, then a scheduled task that stops it on a jittered
# interval and restarts it later — the "take a service down at certain
# intervals, then go quiet" sabotage pattern, in a form that can never hurt
# a real box. The exercise: can monitoring catch the 7036/7045-side storm
# and the hostile task?
#
# Guardrails (not negotiable):
#   - only operates on the dummy service it creates (CCDCSimSvc)
#   - a CRITICAL blocklist is refused outright even if you edit the config
#   - everything restores via wcleanup.ps1

# ------------------------------------------------------------- CONFIG
$Marker      = "ccdc-pb3"
$SvcName     = "CCDCSimSvc"                       # dummy service (created here)
$IntervalMin = 5                                  # sabotage every N minutes
$RestoreMin  = 2                                  # minutes later, restart it
$Rounds      = 8                                  # then the task self-deletes
# ---------------------------------------------------------------------

$ErrorActionPreference = "Stop"
$CRITICAL = @("WinDefend","wuauserv","BITS","wscsvc","Schedule","EventLog",
              "LanmanServer","LanmanWorkstation","Dnscache","Dhcp","RpcSs",
              "SamSs","CryptSvc","ProfSvc","msiserver","Winmgmt","edrsvc")
if ($CRITICAL -contains $SvcName) { throw "refusing: $SvcName is on the critical blocklist" }

$Ledger = "$PSScriptRoot\..\ledger.jsonl"
function Ledger($step, $artifact) {
    $e = @{ ts = [int](Get-Date -UFormat %s); playbook = $Marker; step = $step;
            artifact = $artifact } | ConvertTo-Json -Compress
    Add-Content -Path $Ledger -Value $e
}

# ---- STEP 1: dummy service (a benign sleeper) ----------------------------
$svcExe = "$env:ProgramData\ccdc-simsvc.exe"
Copy-Item "$env:SystemRoot\System32\timeout.exe" $svcExe -Force
sc.exe create $SvcName binPath= "`"$svcExe`" /t 600 /nobreak" start= auto | Out-Null
sc.exe description $SvcName "CCDC simulation dummy service (playbook wb3)"
sc.exe start $SvcName | Out-Null
Ledger "dummy-service" $SvcName

# ---- STEP 2: the sabotage loop (self-limiting, self-deleting) ------------
$loop = "$env:ProgramData\ccdc-pb3-loop.ps1"
@(
  "for (`$r = 0; `$r -lt $Rounds; `$r++) {"
  "  Start-Sleep -Seconds ($IntervalMin*60 + (Get-Random -Maximum 90))  # jitter"
  "  sc.exe stop $SvcName | Out-Null"
  "  Add-Content '$Ledger' ('{ `"ts`": ' + [int](Get-Date -UFormat %s) + ', `"playbook`": `"$Marker`", `"step`": `"svc-stop`", `"artifact`": `"$SvcName`" }')"
  "  Start-Sleep -Seconds ($RestoreMin*60)"
  "  sc.exe start $SvcName | Out-Null"
  "}"
  "Unregister-ScheduledTask -TaskName 'CCDCSimWatch' -Confirm:`$false"
  "Remove-Item '$loop' -Force"
) | Set-Content -Path $loop
Ledger "sabotage-loop" $loop

$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$loop`""
Register-ScheduledTask -TaskName "CCDCSimWatch" -Action $action `
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)) | Out-Null
Ledger "scheduled-task" "\Microsoft\Windows\CCDCSimWatch"

Write-Host "== wb3 armed: $SvcName will stop/restart every ~$IntervalMin min for $Rounds rounds."
Write-Host "   detection targets: service-control storm, hostile task action, the loop script"
Write-Host "cleanup: .\wcleanup.ps1 (deletes task+loop+service)"
