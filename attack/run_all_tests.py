#!/usr/bin/env python3
"""
Master Test Runner: Chay toan bo 5 kich ban kiem thu Purple Team CVE-2026-111497
Ho tro chay tat ca hoac chon tung bai test cu the.
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from common import GREEN, RED, YELLOW, CYAN, BOLD, RESET
import test_01_recon_version
import test_02_differential_probe
import test_03_inbound_waf_and_dos
import test_04_outbound_ssrf_client
import test_05_edr_rce_telemetry


SUITE = [
    ("01", "Test 01: Ra soat Phien ban Binary & C++ Brotli", test_01_recon_version.run_test),
    ("02", "Test 02: Kiem thu Vi sai Giai nen (0x3b vs 0xff)", test_02_differential_probe.run_test),
    ("03", "Test 03: Chot chan WAF Inbound & Chong sap Stream", test_03_inbound_waf_and_dos.run_test),
    ("04", "Test 04: Kiem thu Phoi nhiem HTTP Client Chieu ra", test_04_outbound_ssrf_client.run_test),
    ("05", "Test 05: Phat hien RCE Hậu khai thác (Falco eBPF)", test_05_edr_rce_telemetry.run_test),
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Node2Shell (CVE-2026-111497) Purple Team Automated Test Runner"
    )
    parser.add_argument(
        "-t", "--test",
        help="Chi chay bai test cu the (vi du: 01, 02, 03, 04, 05)",
        choices=["01", "02", "03", "04", "05"]
    )
    parser.add_argument(
        "--skip-edr",
        action="store_true",
        help="Bo qua Test 05 (Falco eBPF) khi dang chay tren WSL2 khong ho tro eBPF"
    )
    parser.add_argument(
        "-o", "--output",
        help="Xuat ket qua tong hop ra file JSON (vi du: report.json)"
    )
    args = parser.parse_args()

    print(f"{BOLD}{CYAN}=========================================================================={RESET}")
    print(f"{BOLD}{CYAN}   BO KIEM THU TU DONG PURPLE TEAM LAB - CVE-2026-111497 (NODE2SHELL)     {RESET}")
    print(f"{BOLD}{CYAN}=========================================================================={RESET}")

    results = []
    for code, name, func in SUITE:
        if args.test and args.test != code:
            continue
        if args.skip_edr and code == "05":
            print(f"\n{YELLOW}[SKIP] Bo qua {name} (--skip-edr){RESET}")
            continue

        try:
            passed = bool(func())
        except Exception as exc:
            print(f"[-] {RED}Loi ngoai le khi chay {name}: {exc}{RESET}")
            passed = False

        results.append({
            "test_id": code,
            "name": name,
            "passed": passed
        })

    print(f"\n{BOLD}{CYAN}====================== BANG TONG HOP KET QUA (SCORECARD) ======================{RESET}")
    passed_count = 0
    for item in results:
        badge = f"{GREEN}[ PASS ]{RESET}" if item["passed"] else f"{RED}[ FAIL / WARN ]{RESET}"
        print(f"  {badge}  {item['name']}")
        if item["passed"]:
            passed_count += 1

    total = len(results)
    print(f"{BOLD}-------------------------------------------------------------------------------{RESET}")
    print(f"  Tong so bai kiem thu dat: {BOLD}{passed_count}/{total}{RESET}")
    print(f"{BOLD}==============================================================================={RESET}\n")

    if args.output:
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cve": "CVE-2026-111497",
            "passed": passed_count,
            "total": total,
            "details": results
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"{GREEN}[+] Da luu bao cao JSON tai: {args.output}{RESET}")

    sys.exit(0 if passed_count == total else 1)


if __name__ == "__main__":
    main()
