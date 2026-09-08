$ErrorActionPreference = "Stop"
$root = "$PSScriptRoot\..\custom-walkthrough"
$fail = 0; $ok = 0
Get-ChildItem $root -Directory | Where-Object { $_.Name -ne "_common" } | ForEach-Object {
    $md = Join-Path $_.FullName "WALKTHROUGH.md"
    if (-not (Test-Path $md)) { Write-Output ("MISSING WALKTHROUGH.md  {0}" -f $_.Name); $fail++ }
    else { $ok++ }
    Get-ChildItem "$($_.FullName)\*.ps1" -ErrorAction SilentlyContinue | ForEach-Object {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errs)
        if ($errs.Count -gt 0) { Write-Output ("SYNTAX FAIL  {0}\{1}: {2}" -f $_.Directory.Name, $_.Name, $errs[0].Message); $fail++ }
        else { $ok++ }
    }
}
Write-Output ("--- {0} checks passed, {1} failed ---" -f $ok, $fail)
exit $(if ($fail -gt 0) { 1 } else { 0 })
