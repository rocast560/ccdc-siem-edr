param([double]$Interval = 5, [double]$Jitter = 0.5, [int]$Seconds = 120)
Write-Host "loopback beacon: connect every ${Interval}s +/- $($Jitter*100)% for ${Seconds}s"
Write-Host "expect NET-BEACON after ~60-90s (detector needs several intervals)"
$stop = (Get-Date).AddSeconds($Seconds)
$srv = [System.Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 9443)
$srv.Start()
$rand = [Random]::new()
while ((Get-Date) -lt $stop) {
    try {
        $c = [Net.Sockets.TcpClient]::new("127.0.0.1", 9443)
        Start-Sleep -Milliseconds 2000; $c.Close()
    } catch {}
    $j = $Interval * $Jitter
    Start-Sleep -Seconds ($Interval + ($rand.NextDouble() * 2 - 1) * $j)
}
$srv.Stop()
Write-Host "done - check the LIVE panel for NET-BEACON"
