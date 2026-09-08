Write-Host "[1] hosting a benign CS-style named pipe (msagent_ccdc01) for 60s..."
$srv = New-Object System.IO.Pipes.NamedPipeServerStream("msagent_ccdc01")
$job = Start-Job {
    $c = New-Object System.IO.Pipes.NamedPipeClientStream(".", "msagent_ccdc01")
    $c.Connect(10000); Start-Sleep 55; $c.Dispose()
}
Start-Sleep 2
Write-Host "[2] enumerating live pipes - what the (future) sensor should do:"
[System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "msagent|postex|msse" }
Write-Host "    ^ if the test pipe shows here but no EDR alert exists: the gap is confirmed"
Start-Sleep 50
$srv.Dispose(); Remove-Job $job -Force
Write-Host "done - pipe closed"
