# wt3-image-spam.ps1 -- multiplying full-screen picture popups.
# Every window is a borderless WinForms form in a tracked background job;
# each dismisses on click, wundo.ps1 closes them all. Purely visual.
# ------------------------------------------------------------- CONFIG
$Marker = "ccdc-taunt"
$Count  = 6
$GapSec = 4
$ImagePath = "$env:PUBLIC\Pictures\taunt.png"   # generated if missing
# ---------------------------------------------------------------------

$ErrorActionPreference = "Stop"
$Ledger = "$PSScriptRoot\..\taunt-ledger.jsonl"

if (-not (Test-Path $ImagePath)) {
    Add-Type -AssemblyName System.Drawing
    New-Item -ItemType Directory -Force -Path (Split-Path $ImagePath) | Out-Null
    $bmp = New-Object Drawing.Bitmap 1280, 720
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.Clear([Drawing.Color]::FromArgb(16, 20, 26))
    $font = New-Object Drawing.Font "Consolas", 48, ([Drawing.FontStyle]::Bold)
    $fmt = New-Object Drawing.StringFormat
    $fmt.Alignment = [Drawing.StringAlignment]::Center
    $g.DrawString("YOU HAVE BEEN TAUNTED", $font, [Drawing.Brushes]::Orange,
                  (New-Object Drawing.RectangleF 0, 300, 1280, 120), $fmt)
    $g.Dispose()
    $bmp.Save($ImagePath, [Drawing.Imaging.ImageFormat]::Png)
}

$popup = {
    param($img)
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $f = New-Object Windows.Forms.Form
    $f.Text = "CCDC_TAUNT_WINDOW"
    $f.FormBorderStyle = "None"
    $f.WindowState = "Maximized"
    $f.TopMost = $true
    $pic = New-Object Windows.Forms.PictureBox
    $pic.Dock = "Fill"
    $pic.SizeMode = "Zoom"
    $pic.Image = [Drawing.Image]::FromFile($img)
    $dismiss = { $form.Close() }
    $f.Add_Click($dismiss)
    $pic.Add_Click($dismiss)
    $f.Controls.Add($pic)
    $f.ShowDialog() | Out-Null
}

for ($i = 1; $i -le $Count; $i++) {
    Start-Job -ScriptBlock $popup -ArgumentList $ImagePath | Out-Null
    Add-Content -Path $Ledger -Value (@{ ts = [int](Get-Date -UFormat %s);
        playbook = $Marker; step = "image-popup"; index = $i } | ConvertTo-Json -Compress)
    Write-Host "== popup $i/$Count up (click to dismiss one; wundo closes all)"
    if ($i -lt $Count) { Start-Sleep -Seconds $GapSec }
}
Write-Host "== done. undo: .\wundo.ps1"
