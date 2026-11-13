#!/usr/bin/env python3
"""
TEST 01: Ra soat Phien ban Binary Runtime & Thu vien C++ Brotli
Phan loai: White-box / Configuration Audit
"""

import json
import sys
from common import DIRECT_APP_URL, GREEN, RED, YELLOW, BOLD, RESET, http_request, print_banner


def parse_version(v_str: str):
    clean = v_str.lstrip("v").split("-")[0]
    return tuple(int(x) for x in clean.split(".") if x.isdigit())


def run_test(target_url: str = DIRECT_APP_URL) -> bool:
    print_banner("TEST 01: KIEM TRA PHIEN BAN RUNTIME & THU VIEN BROTLI")
    status, _, body = http_request(f"{target_url}/api/info")

    if status != 200:
        print(f"[-] {RED}Khong the ket noi toi {target_url}/api/info (HTTP {status}): {body}{RESET}")
        return False

    try:
        info = json.loads(body)
    except json.JSONDecodeError:
        print(f"[-] {RED}Phan hoi khong phai JSON hop le.{RESET}")
        return False

    node_ver = info.get("nodeVersion", "unknown")
    brotli_ver = info.get("brotliVersion", "0.0.0")

    print(f"[*] Target URL     : {target_url}")
    print(f"[*] Node.js Binary : {BOLD}{node_ver}{RESET}")
    print(f"[*] C++ libbrotli  : {BOLD}{brotli_ver}{RESET}")

    b_ver = parse_version(brotli_ver)
    # Cac ban va an toan cua Google Brotli: 1.0.10, 1.1.1, 1.2.1+
    is_safe = (
        (b_ver >= (1, 2, 1)) or
        ((1, 1, 1) <= b_ver < (1, 2, 0)) or
        ((1, 0, 10) <= b_ver < (1, 0, 11))
    )

    if is_safe:
        print(f"\n[+] KET LUAN: {GREEN}{BOLD}[PASS - DA VA]{RESET} Thu vien Brotli ({brotli_ver}) an toan truoc CVE-2026-111497.")
        return True
    else:
        print(f"\n[!] KET LUAN: {YELLOW}{BOLD}[WARN - CHUA VA]{RESET} Thu vien Brotli ({brotli_ver}) nam trong dai bi anh huong (1.0.3 - 1.2.0)!")
        return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DIRECT_APP_URL
    sys.exit(0 if run_test(target) else 1)
