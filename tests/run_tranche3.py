"""Run only the tranche-3 tests (ICMP, tcp_bind, memory scan, config autoblock).
Usage: python tests/run_tranche3.py"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import run_tests as rt

def main():
    s = rt.api("/api/state")
    print("[*] kernel:", s["stats"].get("kernel_trace", "")[:60])
    try:
        rt.t_memory_scan()
        rt.t_config_extraction_autoblock()
        rt.t_icmp_beacon()
        rt.t_tcp_bind_listener()
    finally:
        rt.cleanup()
    passed = sum(1 for _, ok, _ in rt.results if ok)
    print("\n=== TRANCHE-3: %d/%d passed ===" % (passed, len(rt.results)))
    for name, ok, detail in rt.results:
        print(("  PASS " if ok else "  FAIL ") + name + ("  -- " + detail if detail and not ok else ""))
    sys.exit(0 if passed == len(rt.results) else 1)

if __name__ == "__main__":
    main()
