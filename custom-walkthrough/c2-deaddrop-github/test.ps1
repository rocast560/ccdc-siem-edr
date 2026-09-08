param([Parameter(Mandatory=$true)][string]$GistUrl, [int]$Interval = 30, [int]$Minutes = 5)
# Benign dead-drop resolver simulation: polls the gist every $Interval s from a
# NON-browser process, resolves TAVERN=<ip:port>, and (optionally) launches sysupd.exe.
$stop = (Get-Date).AddMinutes($Minutes)
Write-Host "dead-drop poller running for $Minutes min (Ctrl+C to stop)"
while ((Get-Date) -lt $stop) {
    try {
        $line = (Invoke-WebRequest -UseBasicParsing $GistUrl -TimeoutSec 10).Content.Trim()
        if ($line -match 'TAVERN=(.+)') {
            Write-Host ("resolved C2 endpoint from gist: " + $Matches[1])
            if (Test-Path C:\Users\Public\sysupd.exe) {
                Write-Host "(real-implant mode: sysupd.exe would now callback via that endpoint)"
            }
        }
    } catch { Write-Host "gist unreachable (ok - the connection attempt is the signal)" }
    Start-Sleep $Interval
}
