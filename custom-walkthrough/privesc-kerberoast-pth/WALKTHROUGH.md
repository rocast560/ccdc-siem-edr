# Test: Privilege escalation / credential access — Kerberoasting & Pass-the-Hash

**Chain:** domain-side credential attacks. Kerberoasting requests service tickets with
**RC4 (0x17)** encryption and cracks them offline; Pass-the-Hash replays a stolen NTLM
hash for network logons. Both have canonical event-log signatures.

**Requires a domain-joined lab** (a DC or at least a domain account + SPNs). On a
standalone workgroup server these tests are N/A — that's the honest first finding.

**Implant setup:** [`../_common/implant-build.md`](../_common/implant-build.md) not
required; the tests are credential requests, not implant runs.

**Manual steps (domain-joined victim, any user shell):**

```powershell
# --- Kerberoasting (Rubeus is the red-team tool; manual equivalent:) ---
# request a TGS for an SPN account while forcing RC4:
klist purge
net use \\DC01\IPC$ /user:domain\svc_sql Passw0rd    # establish a TGT first (real attack uses valid creds)
# Rubeus: Rubeus.exe kerberoast /rc4opsec   -> one 4769 with 0x17 per roasted SPN
# verify on the DC's Security log:
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 20 |
  Where-Object { $_.Message -match '0x17' } | Select TimeCreated, Message

# --- Pass-the-Hash (manual: any NTLM over-the-shoulder tool; Windows-native:) ---
# (attack tooling: impacket psexec.py -hashes :<NTLM>  or mimikatz sekurlsa::pth)
# detection signal: 4624 LogonType 3 with NTLM auth package on the TARGET:
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 50 |
  Where-Object { $_.Message -match 'Logon Type:\s+3' -and $_.Message -match 'NTLM' } |
  Select TimeCreated, @{n='User';e={($_.Properties[5].Value)}}
```

**Expected vs gap (your EDR):**

| Signal | Today |
|---|---|
| 4769 with RC4 | ❌ GAP — the eventlog sensor doesn't consume 4769 at all |
| 4624 LogonType 3 NTLM (PtH) | ❌ GAP — 4624 not consumed (deliberately: very noisy; needs filtering to NTLM + non-machine accounts) |
| 4648 explicit credentials (WinRM/PS remote) | ❌ GAP — 4648 not consumed |
| mimikatz-style `sekurlsa::pth` command line | ✅ `PROC-MIMIKATZ-CLI` if run from a visible process |

**Fix to file:** add `4769` (filtered server-side to `0x17` ticket-encryption in the
event XML via `TicketEncryptionType` Data) and `4648` to the eventlog sensor's channels;
4624 only with a pre-filter (NTLM + LogonType 3/9 + exclude machine `$` accounts) or it
will flood the pipeline — this is the one channel that genuinely needs care.

**Cleanup:** none (read-only requests).
