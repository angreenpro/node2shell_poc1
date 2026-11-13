#!/usr/bin/env python3
"""
TEST 02: Kiem thu Vi sai Hanh vi Giai nen Brotli (Differential Control Check)
Su dung cap byte doi chung an toan:
  - 0x3b : Luong Brotli rong hop le (1 byte)
  - 0xff : Luong Brotli hong dinh dang (1 byte)
  - 'x'  : Content-Encoding khong ho tro
"""

import sys
from common import WAF_URL, DIRECT_APP_URL, GREEN, RED, YELLOW, BOLD, RESET, http_request, print_banner

VALID_EMPTY_BROTLI = bytes.fromhex("3b")
MALFORMED_BROTLI = bytes.fromhex("ff")


def check_endpoint_behavior(label: str, base_url: str, expect_waf_block: bool) -> bool:
    endpoint = f"{base_url}/api/upload"
    print(f"\n{BOLD}---> Dang kiem tra muc tieu: {label} ({endpoint}){RESET}")

    st_valid, _, body_valid = http_request(
        endpoint,
        method="POST",
        headers={"Content-Encoding": "br", "Content-Type": "application/json"},
        data=VALID_EMPTY_BROTLI
    )

    st_malformed, _, body_malformed = http_request(
        endpoint,
        method="POST",
        headers={"Content-Encoding": "br", "Content-Type": "application/json"},
        data=MALFORMED_BROTLI
    )

    st_unsup, _, _ = http_request(
        endpoint,
        method="POST",
        headers={"Content-Encoding": "x", "Content-Type": "application/json"},
        data=b"x"
    )

    print(f"  ├── Goi 1 [Valid Empty Brotli 0x3b] : HTTP {st_valid} | Body: {body_valid.strip()}")
    print(f"  ├── Goi 2 [Malformed Brotli   0xff] : HTTP {st_malformed} | Body: {body_malformed.strip()}")
    print(f"  └── Goi 3 [Unsupported Enc     'x'] : HTTP {st_unsup}")

    if expect_waf_block:
        if st_valid == 415 and st_malformed == 415:
            print(f"  => DANH GIA: {GREEN}[PASS - DA CO LAP TAI WAF]{RESET} Ca goi 0x3b va 0xff deu bi chan (HTTP 415).")
            return True
        else:
            print(f"  => DANH GIA: {RED}[FAIL]{RESET} WAF khong chan duoc cac goi tin Brotli doi chung!")
            return False
    else:
        if st_valid == 200 and st_malformed == 400:
            print(f"  => DANH GIA: {GREEN}[PASS - XAC NHAN TIN HIEU VI SAI]{RESET} Backend phan biet ro 0x3b (200) va 0xff (400).")
            return True
        else:
            print(f"  => DANH GIA: {YELLOW}[WARN]{RESET} Phan hoi khong khop mau vi sai (Valid={st_valid}, Malformed={st_malformed}).")
            return False


def run_test() -> bool:
    print_banner("TEST 02: PHAN TICH VI SAI BE MAT GIAI NEN (0x3b vs 0xff)")
    waf_ok = check_endpoint_behavior("Qua Chot chan Nginx WAF", WAF_URL, expect_waf_block=True)
    direct_ok = check_endpoint_behavior("Di thang vao Backend (Bypass WAF)", DIRECT_APP_URL, expect_waf_block=False)
    return waf_ok and direct_ok


if __name__ == "__main__":
    sys.exit(0 if run_test() else 1)
