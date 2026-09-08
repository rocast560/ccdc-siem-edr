# VICTIM - step 8: remove everything this walkthrough created + fresh baseline.
$ErrorActionPreference = "SilentlyContinue"
Stop-Process -Name sysupd -Force
# kill ONLY the fake svchost staged under \Users\Public\ - never the system one
Get-Process svchost -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "C:\Users\Public\*" } | Stop-Process -Force

Remove-Item -Recurse -Force C:\Users\Public\SigCheck, C:\Users\Public\DefCheck, C:\Users\Public\Intel
Remove-Item C:\Users\Public\sysupd.exe, C:\Users\Public\svchost.exe, C:\Users\Public\sideload_proof.txt -Force

Write-Host "cleanup done - fresh EDR baseline + clean-audit check:"
Invoke-RestMethod -Method Post "http://127.0.0.1:8420/api/baseline" | Out-Null
$audit = Invoke-RestMethod -Method Post "http://127.0.0.1:8420/api/audit"
if ($audit.findings.Count -eq 0) { Write-Host "clean: no residual findings" }
else { Write-Host "residual findings:"; $audit.findings }
