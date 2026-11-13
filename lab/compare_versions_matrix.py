#!/usr/bin/env python3
"""
Multi-Version Node.js Simulation & Differential Comparison Runner
Kiem thu dong loat cac phien ban Node.js (v20.19.5, v22.23.3, v24.22.0 vs v22.23.4, v24.22.2)
Khong can cai them bat ky thu vien ngoai nao (0 dependencies - chay ngay tren Kali VM).
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple, List

DEFAULT_HOST = os.environ.get("LAB_HOST_IP", "localhost")

TARGETS = [
    ("Node 20.19.5 (Vuln)", 3020),
    ("Node 22.23.3 (Vuln)", 3022),
    ("Node 24.22.0 (Vuln)", 3024),
    ("Node 22.23.4 (Patched)", 3025),
    ("Node 24.22.2 (Patched)", 3026),
]

VALID_EMPTY_BR = bytes.fromhex("3b")
MALFORMED_BR = bytes.fromhex("ff")
SIM_CVE_PROBE = bytes.fromhex("8b000046a440861f6aaf2f0409414a10")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def http_req(url: str, method: str = "GET", headers: Dict[str, str] = None, data: bytes = None) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.getcode(), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def test_single_version(label: str, base_url: str) -> Dict[str, Any]:
    # 1. Lay thong tin version (/api/info)
    st_info, body_info = http_req(f"{base_url}/api/info")
    if st_info != 200:
        return {
            "label": label,
            "url": base_url,
            "online": False,
            "error": body_info
        }

    info = json.loads(body_info)

    # 2. Gui 3 goi tin doi chung (Valid 0x3b, Malformed 0xff, va CVE Probe 8b000046a4...)
    hdr = {"Content-Encoding": "br", "Content-Type": "application/json"}
    st_valid, _ = http_req(f"{base_url}/api/upload", method="POST", headers=hdr, data=VALID_EMPTY_BR)
    st_mal, _ = http_req(f"{base_url}/api/upload", method="POST", headers=hdr, data=MALFORMED_BR)
    st_probe, _ = http_req(f"{base_url}/api/upload", method="POST", headers=hdr, data=SIM_CVE_PROBE)

    # 3. Kiem tra Outbound Fetch mac dinh
    st_out, body_out = http_req(f"{base_url}/api/webhook-test")
    out_exposed = True
    if st_out == 200:
        try:
            out_exposed = json.loads(body_out).get("exposedToMaliciousBrotliResponse", True)
        except Exception:
            pass

    # Logic ket luan theo Differential Oracle (giong scanner.py):
    # Neu st_probe == st_valid (200) -> VULNERABLE
    # Neu st_probe == st_mal (400)   -> PATCHED / NOT VULNERABLE
    is_vuln_probe = (st_probe == st_valid == 200)

    return {
        "label": label,
        "url": base_url,
        "online": True,
        "nodeVersion": info.get("nodeVersion"),
        "brotliVersion": info.get("brotliVersion"),
        "valid_0x3b_http": st_valid,
        "malformed_0xff_http": st_mal,
        "cve_probe_http": st_probe,
        "outbound_br_exposed": out_exposed,
        "verdict": "VULNERABLE" if is_vuln_probe else "PATCHED (SAFE)"
    }


def main():
    parser = argparse.ArgumentParser(description="Simulate & Compare Multiple Node.js Versions for CVE-2026-111497")
    parser.add_argument("-H", "--host", default=DEFAULT_HOST, help="IP hoac Hostname cua may chay Docker (Mac dinh: localhost)")
    parser.add_argument("-o", "--output", help="Luu bang so sanh ra file JSON (vi du: matrix_results.json)")
    args = parser.parse_args()

    print(f"\n{CYAN}{BOLD}=================================================================================================={RESET}")
    print(f"{CYAN}{BOLD}   MA TRAN MO PHONG & DOI CHUNG CAC PHIEN BAN NODE.JS - CVE-2026-111497 (NODE2SHELL)              {RESET}")
    print(f"{CYAN}{BOLD}   Target Host: {args.host}                                                                        {RESET}")
    print(f"{CYAN}{BOLD}=================================================================================================={RESET}\n")

    header_fmt = "{:<24} | {:<10} | {:<10} | {:<10} | {:<10} | {:<11} | {:<16}"
    print(BOLD + header_fmt.format(
        "Phien ban / Profile", "Node Ver", "libbrotli", "Valid(3b)", "Mal(ff)", "Probe(CVE)", "Ket luan (Verdict)"
    ) + RESET)
    print("-" * 102)

    all_results: List[Dict[str, Any]] = []
    for label, port in TARGETS:
        url = f"http://{args.host}:{port}"
        res = test_single_version(label, url)
        all_results.append(res)

        if not res.get("online"):
            print(f"{label:<24} | {RED}OFFLINE ({url}){RESET}")
            continue

        verdict_raw = res["verdict"]
        verdict_colored = (
            f"{RED}{BOLD}{verdict_raw}{RESET}"
            if verdict_raw == "VULNERABLE"
            else f"{GREEN}{BOLD}{verdict_raw}{RESET}"
        )

        print(header_fmt.format(
            res["label"],
            str(res["nodeVersion"]),
            str(res["brotliVersion"]),
            f"HTTP {res['valid_0x3b_http']}",
            f"HTTP {res['malformed_0xff_http']}",
            f"HTTP {res['cve_probe_http']}",
            verdict_colored
        ))

    print("-" * 102)
    print(f"{YELLOW}* Ghi chu Differential Oracle:{RESET}")
    print("  - Khi Probe(CVE) tra ve HTTP 200 (trung voi Valid 0x3b) -> Bo giai nen Brotli bi danh lua (VULNERABLE).")
    print("  - Khi Probe(CVE) tra ve HTTP 400 (trung voi Malformed 0xff) -> Bo giai nen da chan loi (PATCHED).\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)
        print(f"{GREEN}[+] Da xuat ket qua doi chung da phien ban ra file: {args.output}{RESET}\n")


if __name__ == "__main__":
    main()
