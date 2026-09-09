"""IP intelligence (OSINT) enrichment.

Offline (always): RFC range classification (private / loopback / CGNAT /
link-local / multicast / documentation / reserved), and a small static list
of infrastructure ranges that should never appear as C2 peers.

Online (free, no API key, opt-out via EDR_ONLINE_INTEL=0):
- reverse DNS (socket.gethostbyaddr)
- RIPEstat: whois netname/org/country, announcing ASN + holder, geolocation

Results are cached in edr/state/intel-cache.json with a TTL so repeated
beacon alerts on the same peer cost nothing. Every lookup is best-effort:
offline machines simply get the offline section.
"""
import ipaddress, json, os, socket, threading, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(HERE, "state", "intel-cache.json")
TTL = 6 * 3600
ONLINE = os.environ.get("EDR_ONLINE_INTEL", "1") not in ("0", "false", "no")
TIMEOUT = 6

_cache = {}
_lock = threading.Lock()

def _load():
    global _cache
    try:
        with open(CACHE_FILE) as f:
            _cache = json.load(f)
    except Exception:
        _cache = {}

def _save():
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(_cache, f)
    except Exception:
        pass

def classify(ip):
    """Offline RFC classification + static infrastructure context."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"class": "invalid"}
    # specific named ranges FIRST: python's is_private is True for the
    # documentation/reserved blocks too, which would hide their identity
    for net, name in (("100.64.0.0/10", "CGNAT (RFC6598)"),
                      ("169.254.0.0/16", "link-local"),
                      ("192.0.2.0/24", "documentation (RFC5737)"),
                      ("198.51.100.0/24", "documentation (RFC5737)"),
                      ("203.0.113.0/24", "documentation (RFC5737)"),
                      ("224.0.0.0/4", "multicast"),
                      ("240.0.0.0/4", "reserved (bogon)")):
        if obj in ipaddress.ip_network(net):
            return {"class": name}
    if obj.is_loopback:
        return {"class": "loopback", "note": "same-host (lab/test artifacts)"}
    if obj.is_private:
        return {"class": "private (RFC1918)",
                "note": "internal network - lateral movement, not egress"}
    if obj.is_link_local:
        return {"class": "link-local (APIPA)"}
    if obj.is_multicast:
        return {"class": "multicast"}
    if obj.is_reserved:
        return {"class": "reserved"}
    # well-known infrastructure that should never be a C2 peer
    for net, who in (("8.8.8.0/24", "Google Public DNS"), ("8.8.4.0/24", "Google Public DNS"),
                     ("1.1.1.0/24", "Cloudflare DNS"), ("9.9.9.0/24", "Quad9 DNS")):
        if obj in ipaddress.ip_network(net):
            return {"class": "public", "known_infra": who}
    return {"class": "public"}

def _rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def _ripe(path, resource):
    url = "https://stat.ripe.net/data/%s/data.json?resource=%s" % (path, resource)
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode()).get("data", {})
    except Exception:
        return {}

def _online(ip):
    out = {}
    whois = _ripe("whois", ip)
    records = []
    for group in (whois.get("records") or []):     # each group is a list of kv dicts
        if isinstance(group, dict):
            records.append(group)
        elif isinstance(group, list):
            records.extend(g for g in group if isinstance(g, dict))
    for rec in records:
        key = (rec.get("key") or "").lower()
        if key in ("netname", "descr", "org-name", "org") and key not in out:
            out[key] = rec.get("value")
    geoloc = _ripe("geoloc", ip)
    loc = geoloc.get("loc") or geoloc.get("locations") or []
    if loc:
        first = loc[0] if isinstance(loc, list) else loc
        out["geo"] = (first.get("city") if isinstance(first, dict) else str(first)) or str(first)
    if "country" not in out:
        for rec in records:
            if (rec.get("key") or "").lower() == "country":
                out["country"] = rec.get("value")
                break
    pfx = _ripe("prefix-overview", ip)
    asns = pfx.get("asns") or []
    if asns:
        a = asns[0]
        out["asn"] = "AS%s" % a.get("asn")
        out["asn_holder"] = a.get("holder")
        out["prefix"] = pfx.get("resource") or pfx.get("prefix")
    return out

def enrich(ip, force=False):
    """Full enrichment: offline classification + cached online lookups."""
    ip = str(ip or "").strip()
    if not ip:
        return {"class": "none"}
    with _lock:
        if not _cache:
            _load()
        hit = _cache.get(ip)
        if hit and not force and time.time() - hit.get("_ts", 0) < TTL:
            return hit
    info = {"ip": ip}
    info.update(classify(ip))
    rd = _rdns(ip)
    if rd:
        info["rdns"] = rd
    if ONLINE and info.get("class") == "public":
        try:
            info.update(_online(ip))
        except Exception:
            pass
    info["_ts"] = time.time()
    with _lock:
        _cache[ip] = info
        _save()
    info.pop("_ts", None)
    return info

def enrich_async(ip, alert):
    """Attach enrichment to an existing alert dict (beacon auto-enrichment)."""
    def worker():
        try:
            data = enrich(ip)
            if data.get("class") != "invalid":
                alert.setdefault("data", {})["intel"] = data
        except Exception:
            pass
    threading.Thread(target=worker, daemon=True).start()
