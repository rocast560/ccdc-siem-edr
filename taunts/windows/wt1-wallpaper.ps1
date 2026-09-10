# wt1-wallpaper.ps1 -- the classic CCDC taunt: swap the wallpaper.
# Saves the current wallpaper for undo. Optional -IntervalMin plants a
# scheduled task that re-swaps on a timer (delivery shape: PERS-TASK).
param([int]$IntervalMin = 0)

# ------------------------------------------------------------- CONFIG
$Marker    = "ccdc-taunt"
$ImagePath = "$env:PUBLIC\Pictures\taunt.png"   # set your image; auto-generated if missing
$Text      = "CCDC RED TEAM WAS HERE"
# ---------------------------------------------------------------------

$ErrorActionPreference = "Stop"
$Ledger = "$PSScriptRoot\..\taunt-ledger.jsonl"
function Ledger($step, $detail) {
    Add-Content -Path $Ledger -Value (@{ ts = [int](Get-Date -UFormat %s);
        playbook = $Marker; step = $step; detail = $detail } | ConvertTo-Json -Compress)
}

Add-Type @"
using System.Runtime.InteropServices;
public class WP {
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@

# 1. save the current wallpaper for undo
$orig = (Get-ItemProperty "HKCU:\Control Panel\Desktop").Wallpaper
"$orig" | Set-Content "$PSScriptRoot\.orig-wallpaper"
Ledger "save-original" $orig

# 2. generate a taunt image if none supplied (solid dark + text)
if (-not (Test-Path $ImagePath)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $ImagePath) | Out-Null
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object Drawing.Bitmap 1920, 1080
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.Clear([Drawing.Color]::FromArgb(16, 20, 26))
    $font = New-Object Drawing.Font "Consolas", 72, ([Drawing.FontStyle]::Bold)
    $brush = [Drawing.Brushes]::Orange
    $fmt = New-Object Drawing.StringFormat
    $fmt.Alignment = [Drawing.StringAlignment]::Center
    $g.DrawString($Text, $font, $brush, (New-Object Drawing.RectangleF 0, 460, 1920, 160), $fmt)
    $g.Dispose()
    $bmp.Save($ImagePath, [Drawing.Imaging.ImageFormat]::Png)
}

# 3. apply
[WP]::SystemParametersInfo(20, 0, $ImagePath, 3) | Out-Null   # SPI_SETDESKWALLPAPER
Ledger "wallpaper-set" $ImagePath

# 4. optional interval mode via scheduled task (blue team: PERS-TASK!)
if ($IntervalMin -gt 0) {
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
                -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Register-ScheduledTask -TaskName "CCDCTauntWP" -Action $action `
        -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($IntervalMin) `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMin)) | Out-Null
    Ledger "interval-task" "CCDCTauntWP every $IntervalMin min"
    Write-Host "== interval taunt armed every $IntervalMin min (undo: .\wundo.ps1)"
} else {
    Write-Host "== wallpaper set (was: $orig). undo: .\wundo.ps1"
}
