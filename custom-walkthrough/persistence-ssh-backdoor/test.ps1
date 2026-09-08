Write-Host "[1] installing OpenSSH Server (expect EVT-7045 + PERS-SERVICE)..."
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
Start-Service sshd; Set-Service sshd -StartupType Automatic
Write-Host "[2] dropping operator key into administrators_authorized_keys (currently a GAP)..."
if (-not (Test-Path "$env:TEMP\testkey")) { ssh-keygen -t ed25519 -f "$env:TEMP\testkey" -N '""' | Out-Null }
Add-Content C:\ProgramData\ssh\administrators_authorized_keys (Get-Content "$env:TEMP\testkey.pub")
Write-Host "[3] opening the firewall Akira-style (currently a GAP)..."
netsh advfirewall firewall add rule name="OpenSSH Server (sshd)" dir=in action=allow protocol=TCP localport=22
Write-Host "done - check the LIVE panel, then cleanup:"
Write-Host '  netsh advfirewall firewall delete rule name="OpenSSH Server (sshd)"'
Write-Host '  (remove your key line from C:\ProgramData\ssh\administrators_authorized_keys)'
