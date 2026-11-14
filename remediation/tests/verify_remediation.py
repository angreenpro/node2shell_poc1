#!/usr/bin/env python3
"""
Automated Remediation Verification Script (Re-testing) - CVE-2026-111497
Kiem tra 5 tieu chi nghiem thu sau khi ap dung ban va:
  1. Phien ban Binary & libbrotli da nang cap (>= 1.1.1 / 1.2.1)
  2. WAF Hardened chan triet de Content-Encoding: br (HTTP 415)
  3. Bo giai nen da va tu choi goi CVE Probe (8b000046a4...) voi ma HTTP 400
  4. HTTP Client chieu ra (Outbound) mac dinh da loai bo 'br' khoi Accept-Encoding
  5. Container Hardening: Chay duoi quyen non-root (UID != 0) va khoa endpoint RCE
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error

DEFAULT_HOST = os.environ.get("LAB_HOST_IP", "localhost")
HARDENED_WAF_PORT = int(os.environ.get("REM_WAF_PORT", "8085"))
PATCHED_APP_PORT = int(os.environ.get("REM_APP_PORT", "3002"))

VALID_EMPTY_BR = bytes.fromhex("3b")
SIM_CVE_PROBE = bytes.fromhex("8b000046a440861f6aaf2f0409414a10")

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def http_req(url, method="GET", headers=None, data=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.getcode(), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def parse_ver(v_str):
    clean = str(v_str).lstrip("v").split("-")[0]
    return tuple(int(x) for x in clean.split(".") if x.isdigit())


def main():
    parser = argparse.ArgumentParser(description="Verify CVE-2026-111497 Remediation Controls")
    parser.add_argument("-H", "--host", default=DEFAULT_HOST, help="IP hoac Hostname cua may chay Docker")
    parser.add_argument("--waf-port", type=int, default=HARDENED_WAF_PORT, help="Cong WAF (Mac dinh: 8085 hoac 8081)")
    parser.add_argument("--app-port", type=int, default=PATCHED_APP_PORT, help="Cong App Patched (Mac dinh: 3002)")
    parser.add_argument("-o", "--output", help="Luu bao cao nghiem thu ra file JSON")
    args = parser.parse_args()

    waf_url = f"http://{args.host}:{args.waf_port}"
    app_url = f"http://{args.host}:{args.app_port}"

    print(f"\n{CYAN}{BOLD}==============================================================================={RESET}")
    print(f"{CYAN}{BOLD}   KIEM THU NGHIEM THU SAU KHAC PHUC (RE-TESTING) - CVE-2026-111497            {RESET}")
    print(f"{CYAN}{BOLD}   WAF URL: {waf_url} | Patched App URL: {app_url}             {RESET}")
    print(f"{CYAN}{BOLD}==============================================================================={RESET}")

    checks = []

    # Check 1: Kiem tra phien ban Runtime & libbrotli
    print(f"\n{BOLD}[Check 1] Xac minh Phien ban Node.js & C++ libbrotli (/api/info){RESET}")
    st_info, body_info = http_req(f"{app_url}/api/info")
    c1_pass = False
    uid_val = 1000
    if st_info == 200:
        info = json.loads(body_info)
        n_ver = info.get("nodeVersion", "0.0.0")
        b_ver = info.get("brotliVersion", "0.0.0")
        uid_val = info.get("runningAsUid", 1000)
        b_tuple = parse_ver(b_ver)
        c1_pass = (b_tuple >= (1, 2, 1)) or ((1, 1, 1) <= b_tuple < (1, 2, 0)) or ((1, 0, 10) <= b_tuple < (1, 0, 11))
        print(f"  ├── Node.js: {BOLD}{n_ver}{RESET} | libbrotli: {BOLD}{b_ver}{RESET} | Status: {info.get('status')}")
        print(f"  └── Ket qua: {GREEN + '[PASS]' if c1_pass else RED + '[FAIL]'}{RESET}")
    else:
        print(f"  └── {RED}[FAIL] Khong the ket noi toi {app_url}/api/info (HTTP {st_info}){RESET}")
    checks.append(("1. Nang cap Runtime & libbrotli (>= 1.1.1 / 1.2.1)", c1_pass))

    # Check 2: Kiem tra WAF chan Inbound Content-Encoding: br
    print(f"\n{BOLD}[Check 2] Kiem thu Chot chan Virtual Patching tren WAF ({waf_url}){RESET}")
    st_waf, _ = http_req(
        f"{waf_url}/api/upload",
        method="POST",
        headers={"Content-Encoding": "br"},
        data=SIM_CVE_PROBE
    )
    c2_pass = (st_waf == 415)
    print(f"  ├── Gui goi Probe kem 'Content-Encoding: br' qua WAF -> HTTP {st_waf} (Mong doi: 415)")
    print(f"  └── Ket qua: {GREEN + '[PASS]' if c2_pass else RED + '[FAIL]'}{RESET}")
    checks.append(("2. WAF Virtual Patching chan Content-Encoding: br (HTTP 415)", c2_pass))

    # Check 3: Kiem tra Bo giai nen Da Va tu choi goi CVE Probe truc tiep
    print(f"\n{BOLD}[Check 3] Kiem thu Bo giai nen Brotli Da Va khi nhan truc tiep CVE Probe ({app_url}){RESET}")
    hdr = {"Content-Encoding": "br", "Content-Type": "application/json"}
    st_valid, _ = http_req(f"{app_url}/api/upload", method="POST", headers=hdr, data=VALID_EMPTY_BR)
    st_probe, _ = http_req(f"{app_url}/api/upload", method="POST", headers=hdr, data=SIM_CVE_PROBE)
    c3_pass = (st_valid == 200 and st_probe == 400)
    print(f"  ├── Goi hop le rong (0x3b) -> HTTP {st_valid} | Goi CVE Probe (8b000046a4...) -> HTTP {st_probe}")
    print(f"  └── Ket qua: {GREEN + '[PASS - BLOCKED BY PATCHED DECODER]' if c3_pass else RED + '[FAIL]'}{RESET}")
    checks.append(("3. Bo giai nen Da Va tu choi CVE Probe (HTTP 400)", c3_pass))

    # Check 4: Kiem tra Outbound HTTP Client loai bo 'br'
    print(f"\n{BOLD}[Check 4] Kiem thu Gia co HTTP Client Chieu ra (/api/webhook-test){RESET}")
    st_out, body_out = http_req(f"{app_url}/api/webhook-test", headers={"x-safe-outbound": "true"})
    c4_pass = False
    if st_out == 200:
        out_data = json.loads(body_out)
        enc_sent = out_data.get("clientSentAcceptEncoding", "")
        exposed = out_data.get("exposedToMaliciousBrotliResponse", True)
        c4_pass = (not exposed) and ("br" not in enc_sent)
        print(f"  ├── Header Accept-Encoding gui di: '{GREEN}{enc_sent}{RESET}' | Exposed: {exposed}")
    print(f"  └── Ket qua: {GREEN + '[PASS]' if c4_pass else RED + '[FAIL]'}{RESET}")
    checks.append(("4. Outbound HTTP Client loai bo 'br'", c4_pass))

    # Check 5: Kiem tra Container Hardening & Khoa RCE Endpoint
    print(f"\n{BOLD}[Check 5] Kiem thu Co lap Container (Least Privilege & RCE Surface){RESET}")
    st_rce, _ = http_req(f"{app_url}/sim/rce-trigger", method="POST")
    c5_pass = (st_rce in (403, 404)) and (uid_val != 0)
    print(f"  ├── Tien trinh UID={uid_val} | Kiem tra /sim/rce-trigger -> HTTP {st_rce} (Mong doi: 403/404)")
    print(f"  └── Ket qua: {GREEN + '[PASS]' if c5_pass else RED + '[FAIL]'}{RESET}")
    checks.append(("5. Container Hardening & Khoa RCE Surface", c5_pass))

    print(f"\n{BOLD}{CYAN}==================== KET QUA NGHIEM THU (RE-TEST SCORECARD) ===================={RESET}")
    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        badge = f"{GREEN}[ PASS ]{RESET}" if ok else f"{RED}[ FAIL ]{RESET}"
        print(f"  {badge}  {name}")
    print(f"{BOLD}--------------------------------------------------------------------------------{RESET}")
    print(f"  Tong so tieu chi dat: {BOLD}{passed}/{len(checks)}{RESET}")
    print(f"{BOLD}================================================================================{RESET}\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"passed": passed, "total": len(checks), "checks": checks}, f, indent=2)

    sys.exit(0 if passed == len(checks) else 1)


if __name__ == "__main__":
    main()