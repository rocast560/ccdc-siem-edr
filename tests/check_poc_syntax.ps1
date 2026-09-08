$ErrorActionPreference = "Stop"
Get-ChildItem "$PSScriptRoot\..\poc-scripts\victim\*.ps1" | ForEach-Object {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errs)
    if ($errs.Count -gt 0) {
        Write-Output ("FAIL {0}: {1}" -f $_.Name, $errs[0].Message)
    } else {
        Write-Output ("OK   {0}" -f $_.Name)
    }
}
