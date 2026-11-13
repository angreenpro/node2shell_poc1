#!/usr/bin/env python3
"""
A/B Lab Comparison Script (Before vs. After Remediation) - CVE-2026-111497
So sanh truc tiep giua Moi truong Chua Va (Target Vuln) va Moi truong Da Va (Remediated)
"""

import argparse
import json
import os
import urllib.request
import urllib.error

DEFAULT_HOST = os.environ.get("LAB_HOST_IP", "localhost")
VALID_EMPTY_BR = bytes.fromhex("3b")
MALFORMED_BR = bytes.fromhex("ff")
SIM_CVE_PROBE = bytes.fromhex("8b000046a440861f6aaf2f0409414a10")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def http_req(url, method="GET", headers=None, data=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=4) as r:
            return r.getcode(), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def inspect_env(base_url):
    st_info, body_info = http_req(f"{base_url}/api/info")
    if st_info != 200:
        return {"online": False, "url": base_url}

    info = json.loads(body_info)
    hdr = {"Content-Encoding": "br", "Content-Type": "application/json"}
    st_valid, _ = http_req(f"{base_url}/api/upload", method="POST", headers=hdr, data=VALID_EMPTY_BR)
    st_mal, _ = http_req(f"{base_url}/api/upload", method="POST", headers=hdr, data=MALFORMED_BR)
    st_probe, _ = http_req(f"{base_url}/api/upload", method="POST", headers=hdr, data=SIM_CVE_PROBE)

    st_out, body_out = http_req(f"{base_url}/api/webhook-test")
    out_enc = "unknown"
    if st_out == 200:
        try:
            out_enc = json.loads(body_out).get("clientSentAcceptEncoding", "unknown")
        except Exception:
            pass

    st_rce, _ = http_req(f"{base_url}/sim/rce-trigger", method="POST")

    return {
        "online": True,
        "url": base_url,
        "nodeVersion": str(info.get("nodeVersion", "N/A")),
        "brotliVersion": str(info.get("brotliVersion", "N/A")),
        "valid_0x3b": f"HTTP {st_valid}",
        "malformed_0xff": f"HTTP {st_mal}",
        "cve_probe": f"HTTP {st_probe} ({'ACCEPTED/VULN' if st_probe == 200 else 'BLOCKED/SAFE'})",
        "outbound_header": out_enc,
        "rce_endpoint": f"HTTP {st_rce}",
        "overall_status": "VULNERABLE" if st_probe == 200 else "PATCHED & HARDENED"
    }


def main():
    parser = argparse.ArgumentParser(description="Compare Vulnerable vs. Patched Lab Environments")
    parser.add_argument("-H", "--host", default=DEFAULT_HOST, help="IP may chu Docker")
    parser.add_argument("--vuln-port", type=int, default=3000, help="Cong container Chua Va (Mac dinh: 3000 hoac 3022)")
    parser.add_argument("--patched-port", type=int, default=3002, help="Cong container Da Va (Mac dinh: 3002 hoac 3025)")
    parser.add_argument("-o", "--output", help="Xuat ket qua so sanh ra file JSON")
    args = parser.parse_args()

    vuln_url = f"http://{args.host}:{args.vuln_port}"
    patched_url = f"http://{args.host}:{args.patched_port}"

    vuln = inspect_env(vuln_url)
    patched = inspect_env(patched_url)

    print(f"\n{CYAN}{BOLD}========================================================================================={RESET}")
    print(f"{CYAN}{BOLD}   BANG DOI CHUNG TRUOC & SAU KHI KHAC PHUC (BEFORE vs. AFTER REMEDIATION)               {RESET}")
    print(f"{CYAN}{BOLD}========================================================================================={RESET}\n")

    fmt = "{:<30} | {:<26} | {:<26}"
    print(BOLD + fmt.format("Tieu chi Kiem thu", f"TRUOC KHI VA (:{args.vuln_port})", f"SAU KHI VA (:{args.patched_port})") + RESET)
    print("-" * 88)

    rows = [
        ("Trang thai Ket noi", "ONLINE" if vuln.get("online") else "OFFLINE", "ONLINE" if patched.get("online") else "OFFLINE"),
        ("1. Node.js Runtime Version", vuln.get("nodeVersion", "-"), patched.get("nodeVersion", "-")),
        ("2. C++ libbrotli Version", vuln.get("brotliVersion", "-"), patched.get("brotliVersion", "-")),
        ("3. Valid Empty Brotli (0x3b)", vuln.get("valid_0x3b", "-"), patched.get("valid_0x3b", "-")),
        ("4. Malformed Brotli (0xff)", vuln.get("malformed_0xff", "-"), patched.get("malformed_0xff", "-")),
        ("5. Phan ung voi CVE Probe", vuln.get("cve_probe", "-"), patched.get("cve_probe", "-")),
        ("6. Outbound Accept-Encoding", vuln.get("outbound_header", "-"), patched.get("outbound_header", "-")),
        ("7. RCE Simulation Surface", vuln.get("rce_endpoint", "-"), patched.get("rce_endpoint", "-")),
        ("8. KET LUAN AN TOAN", vuln.get("overall_status", "-"), patched.get("overall_status", "-")),
    ]

    for label, v_val, p_val in rows:
        print(fmt.format(label, str(v_val), str(p_val)))

    print("-" * 88 + "\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"before_remediation": vuln, "after_remediation": patched}, f, indent=2)
        print(f"{GREEN}[+] Da luu bao cao so sanh A/B tai: {args.output}{RESET}\n")


if __name__ == "__main__":
    main()
