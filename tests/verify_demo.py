"""Demo helper: verify containment of the quarantined test implant."""
import json, urllib.request

def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req))

key = "path:" + r"c:\users\administrator\desktop\ccdc-edr-siem-design\tests\bin\implant.exe"
v = post("http://127.0.0.1:8420/api/implants/verify", {"key": key})
print("VERIFY all_pass:", v["all_pass"], "| status:", v["status"])
for c in v["checks"]:
    print("  ", "PASS" if c["pass"] else "FAIL", "|", c["name"], "|", c["detail"])

d = json.load(urllib.request.urlopen("http://127.0.0.1:8420/api/implants"))
for b in d["implants"][:3]:
    print("entity:", b["name"].ljust(14), "| score", b["score"], "| status", b["status"].ljust(22), "| alive", b["alive"])
