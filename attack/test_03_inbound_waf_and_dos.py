#!/usr/bin/env python3
"""
TEST 03: Kiem thu Chot chan WAF Chieu vao & Kha nang Chong sap (DoS Resilience)
Phan loai: Inbound Defense & Availability Test
"""

import sys
from common import WAF_URL, DIRECT_APP_URL, GREEN, RED, BOLD, RESET, http_request, print_banner


def run_test() -> bool:
    print_banner("TEST 03: KIEM THU CHAN INBOUND WAF & CHONG SAP STREAM ERROR")

    print(f"{BOLD}[Phan A] Kiem tra Rule chan Header tren WAF ({WAF_URL}){RESET}")
    waf_passed = True
    for variant in ["br", "BR", "gzip, br"]:
        status, _, _ = http_request(
            f"{WAF_URL}/api/upload",
            method="POST",
            headers={"Content-Encoding": variant},
            data=b"\x3b"
        )
        print(f"  ├── Thu Header 'Content-Encoding: {variant}' -> HTTP {status}")
        if status != 415:
            waf_passed = False

    if waf_passed:
        print(f"  └── Ket qua Phan A: {GREEN}[PASS]{RESET} WAF chan triet de moi bien the Content-Encoding chua 'br'.")
    else:
        print(f"  └── Ket qua Phan A: {RED}[FAIL]{RESET} WAF de lot bien the Header!")

    print(f"\n{BOLD}[Phan B] Kiem tra Chong sap Event Loop khi nhan luong byte loi ({DIRECT_APP_URL}){RESET}")
    corrupted_samples = [
        b"\x1b\x00\x00\xff\xff",
        b"\xff\xff\xff\xff",
        b"\x8b\x00\x00\x46\xa4",
    ]

    for idx, payload in enumerate(corrupted_samples, 1):
        st, _, body = http_request(
            f"{DIRECT_APP_URL}/api/upload",
            method="POST",
            headers={"Content-Encoding": "br"},
            data=payload
        )
        print(f"  ├── Mau loi #{idx} ({payload.hex()}) -> Backend tra ve HTTP {st}: {body.strip()}")

    alive_status, _, _ = http_request(f"{DIRECT_APP_URL}/api/info")
    if alive_status == 200:
        print(f"  └── Ket qua Phan B: {GREEN}[PASS]{RESET} Tien trinh Node.js van hoat dong on dinh (Alive Check HTTP 200).")
        return waf_passed and True
    else:
        print(f"  └── Ket qua Phan B: {RED}[FAIL - SERVER CRASHED]{RESET} Tien trinh Node.js bi sap sau khi nhan luong loi!")
        return False


if __name__ == "__main__":
    sys.exit(0 if run_test() else 1)
