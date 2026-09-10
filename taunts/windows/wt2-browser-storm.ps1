# wt2-browser-storm.ps1 -- staggered browser tabs (default: the canonical
# rickroll). PIDs are tracked for undo (undo closes the browser processes
# this script spawned - warn the victim not to have unsaved tabs first).
# ------------------------------------------------------------- CONFIG
$Marker = "ccdc-taunt"
$Tabs   = 5
$GapSec = 7
$Urls   = @("https://www.youtube.com/watch?v=dQw4w9WgXcQ")
# ---------------------------------------------------------------------

$Ledger = "$PSScriptRoot\..\taunt-ledger.jsonl"
$pids = @()
foreach ($i in 1..$Tabs) {
    $u = $Urls[(Get-Random -Maximum $Urls.Count)]
    $p = Start-Process -FilePath $u -PassThru       # default browser
    $pids += $p.Id
    Add-Content -Path $Ledger -Value (@{ ts = [int](Get-Date -UFormat %s);
        playbook = $Marker; step = "tab-open"; pid = $p.Id; url = $u } | ConvertTo-Json -Compress)
    Write-Host "== tab $i/$Tabs opened (pid $($p.Id))"
    if ($i -lt $Tabs) { Start-Sleep -Seconds $GapSec }
}
$pids -join "," | Set-Content "$PSScriptRoot\.tab-pids"
Write-Host "== done. undo: .\wundo.ps1 (closes the spawned browser processes)"
