# Test: C2 channel — named-pipe beacons (Cobalt Strike SMB pivot)

**Chain:** Cobalt Strike's SMB beacons chain through **named pipes** — default names like
`msagent_XXXX` — letting implants talk peer-to-peer with no network egress at all. Your
signature pack knows the names statically; this test checks whether anything detects a
live pipe. (Reference: [Cobalt Strike's own named-pipe pivoting post](https://www.cobaltstrike.com/blog/named-pipe-pivoting).)

**Implant setup:** none needed — the test hosts a benign named-pipe server.

**Victim (any PowerShell):** `.\test.ps1` creates the pipe and a client that talks over
it for a minute:

```powershell
# server side (the "beacon"): a pipe named like CS defaults
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream("msagent_ccdc01")
# client side (the "pivot peer"):
$c = New-Object System.IO.Pipes.NamedPipeClientStream(".", "msagent_ccdc01")
# enumerate live pipes - what your sensor SHOULD be doing each cycle:
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String msagent
```

**Expected vs gap:**

| Signal | Today |
|---|---|
| Pipe created | ❌ GAP — no runtime pipe enumeration; a live CS SMB beacon would be invisible |
| `msagent_` string in a dropped binary | ✅ `SIG-CS-BEACON` statically — but says nothing about live pipes |

**Fix to file:** a sensor cycle running
`[IO.Directory]::GetFiles("\\.\pipe\")` diffed against a baseline pipe list + known-bad
patterns (`msagent_`, `postex_`, `status_`, `msse_`) → `NET-PIPE` alert (critical).
Cheap, fast, and closes a real C2 channel — highest-value network-side fix available.

**Cleanup:** automatic (script disposes both ends).
