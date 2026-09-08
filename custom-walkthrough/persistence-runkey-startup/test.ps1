if (-not (Test-Path C:\Users\Public\sysupd.exe)) {
    Write-Warning "stage the implant first (any delivery-* walkthrough)"; exit 1
}
Write-Host "[1] Run key (expect PERS-RUNKEY)..."
New-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run `
  -Name CCDCTestPayload -Value "C:\Users\Public\sysupd.exe" -PropertyType String -Force | Out-Null
Start-Sleep 35
Write-Host "[2] Startup folder item (expect PERS-STARTUP)..."
Set-Content "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ccdc-test-persistence.bat" "@echo ccdc test"
Write-Host "auditor diffs fire within 30s of each"
