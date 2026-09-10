# wundo.ps1 -- undo every taunt: restore wallpaper, close spawned
# browsers, close taunt windows, remove the interval task.
$ErrorActionPreference = "SilentlyContinue"

# 1. wallpaper back
$origFile = "$PSScriptRoot\.orig-wallpaper"
if (Test-Path $origFile) {
    Add-Type @"
using System.Runtime.InteropServices;
public class WP {
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
    $orig = (Get-Content $origFile -First 1)
    if ($orig -and (Test-Path $orig)) {
        [WP]::SystemParametersInfo(20, 0, $orig, 3) | Out-Null
        Write-Host "wallpaper restored: $orig"
    }
    Remove-Item $origFile
}

# 2. browser processes this session spawned
$pidFile = "$PSScriptRoot\.tab-pids"
if (Test-Path $pidFile) {
    foreach ($p in ((Get-Content $pidFile) -split ",")) {
        if ($p) { Stop-Process -Id ([int]$p) -Force -ErrorAction SilentlyContinue }
    }
    Remove-Item $pidFile
    Write-Host "spawned browser processes closed"
}

# 3. taunt popup jobs + any windows carrying the taunt title
Get-Job | Where-Object { $_.State -eq "Running" } | Stop-Job
Get-Process | Where-Object { $_.MainWindowTitle -eq "CCDC_TAUNT_WINDOW" } | Stop-Process -Force

# 4. interval task
Unregister-ScheduledTask -TaskName "CCDCTauntWP" -Confirm:$false
Write-Host "== taunts undone."
