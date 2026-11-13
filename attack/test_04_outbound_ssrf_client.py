#!/usr/bin/env python3
"""
TEST 04: Kiem thu Phoi nhiem Chieu ra (Outbound HTTP Client 'Accept-Encoding')
Phan loai: Client-Side / SSRF Vector Assessment
"""

import json
import sys
from common import WAF_URL, GREEN, RED, YELLOW, BOLD, RESET, http_request, print_banner


def run_test(base_url: str = WAF_URL) -> bool:
    print_banner("TEST 04: KIEM THU PHOI NHIEM CHIEU RA (OUTBOUND FETCH CLIENT)")

    st1, _, body1 = http_request(f"{base_url}/api/webhook-test")
    st2, _, body2 = http_request(
        f"{base_url}/api/webhook-test",
        headers={"x-safe-outbound": "true"}
    )

    if st1 != 200 or st2 != 200:
        print(f"[-] {RED}Loi ket noi toi endpoint /api/webhook-test (HTTP {st1}/{st2}){RESET}")
        return False

    try:
        res_default = json.loads(body1)
        res_mitigated = json.loads(body2)
    except json.JSONDecodeError:
        print(f"[-] {RED}Phan hoi JSON khong hop le.{RESET}")
        return False

    enc_default = res_default.get("clientSentAcceptEncoding", "")
    enc_mitigated = res_mitigated.get("clientSentAcceptEncoding", "")

    print(f"[*] Trang thai 1 (Fetch Mac dinh cua Node.js):")
    print(f"    ├── Header gui ra ngoai : {YELLOW}{BOLD}{enc_default}{RESET}")
    print(f"    └── Phoi nhiem voi Brotli: {RED}{res_default.get('exposedToMaliciousBrotliResponse')}{RESET}")

    print(f"\n[*] Trang thai 2 (Sau khi ap dung Mitigation ep Header):")
    print(f"    ├── Header gui ra ngoai : {GREEN}{BOLD}{enc_mitigated}{RESET}")
    print(f"    └── Phoi nhiem voi Brotli: {GREEN}{res_mitigated.get('exposedToMaliciousBrotliResponse')}{RESET}")

    if not res_mitigated.get("exposedToMaliciousBrotliResponse") and "br" not in enc_mitigated:
        print(f"\n[+] KET LUAN: {GREEN}{BOLD}[PASS]{RESET} Da loai bo hoan toan 'br' khoi cac yeu cau HTTP chieu ra.")
        return True
    else:
        print(f"\n[!] KET LUAN: {RED}{BOLD}[FAIL]{RESET} Ung dung van chap nhan du lieu Brotli tu may chu ben ngoai!")
        return False


if __name__ == "__main__":
    sys.exit(0 if run_test() else 1)
