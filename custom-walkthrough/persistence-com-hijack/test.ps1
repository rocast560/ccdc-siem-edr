Write-Host "[1] shadowing a CLSID in HKCU (expect PERS-COM within 30s)..."
New-Item -Path "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" `
  -Name "(default)" -Value "C:\Users\Public\comhost.dll"
Write-Host "done - the auditor diff is the detection; no process needs to run"
Write-Host "cleanup: Remove-Item -Recurse 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}'"
