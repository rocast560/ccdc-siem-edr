Write-Host "[1] creating hidden-named account (expect EVT-4720)..."
net user cdcbackup$ Passw0rd! /add
Write-Host "[2] adding to Administrators (expect EVT-4732)..."
net localgroup administrators cdcbackup$ /add
Write-Host "[3] proof of hiding from legacy enumeration:"
net user | Select-String cdcbackup
Write-Host "    ^ nothing? correct - the `$ name hides from net user"
Get-LocalUser | Where-Object Name -like "cdcbackup*"
Write-Host "    ^ but visible to Get-LocalUser - which is what the auditor fix should use"
Write-Host "cleanup: net user cdcbackup$ /delete"
