Write-Host "[1] ensuring WinRM is enabled..."
try { Enable-PSRemoting -Force -ErrorAction Stop } catch { Write-Host "    already enabled or error: $_" }
Write-Host "[2] invoking a loopback remoting session (wsmprovhost should appear)..."
Invoke-Command -ComputerName localhost -ScriptBlock { whoami; hostname } -ErrorAction SilentlyContinue
Write-Host "[3] session-host check..."
Get-Process wsmprovhost -ErrorAction SilentlyContinue | Select-Object Name, Id | Format-Table -AutoSize
Write-Host "4648/4624 correlation = filed gaps (channels not consumed yet)"
