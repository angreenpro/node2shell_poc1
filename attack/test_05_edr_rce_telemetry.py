#!/usr/bin/env python3
"""
TEST 05: Kiem thu Kha nang Phat hien Hau khai thac (Post-Exploitation RCE Telemetry)
Phan loai: Runtime EDR / eBPF Detection Verification (Chay chuan nhat tren Fedora Linux)
"""

import subprocess
import time
import sys
from common import WAF_URL, FALCO_CONTAINER, GREEN, RED, YELLOW, BOLD, RESET, http_request, print_banner


def run_test(base_url: str = WAF_URL) -> bool:
    print_banner("TEST 05: KIEM THU PHAT HIEN RCE (NODE2SHELL) TREN FALCO eBPF")

    print(f"[*] Buoc 1: Kich hoat gia lap hanh vi tien trinh 'node' sinh ra '/bin/sh'...")
    status, _, body = http_request(f"{base_url}/sim/rce-trigger", method="POST")

    if status != 200:
        print(f"[-] {RED}Khong the kich hoat endpoint /sim/rce-trigger (HTTP {status}){RESET}")
        return False

    print(f"    └── Phan hoi tu Target App: {body.strip().replace(chr(10), ' | ')}")

    print(f"\n[*] Buoc 2: Doi 2 giay de Falco eBPF thu thap su kien syscall 'execve' tu Kernel...")
    time.sleep(2)

    print(f"[*] Buoc 3: Truy van log canh bao tu container '{FALCO_CONTAINER}'...")
    try:
        proc = subprocess.run(
            ["docker", "logs", "--tail", "50", FALCO_CONTAINER],
            capture_output=True,
            text=True,
            timeout=5
        )
        logs = proc.stdout + proc.stderr
        alerts = [line for line in logs.splitlines() if "NODE2SHELL" in line or "CRITICAL" in line]

        if alerts:
            print(f"    └── {GREEN}Tim thay canh bao tu Falco EDR:{RESET}")
            print(f"        {BOLD}{alerts[-1]}{RESET}")
            print(f"\n[+] KET LUAN: {GREEN}{BOLD}[PASS]{RESET} He thong EDR/eBPF da bat chinh xac hanh vi Node.js goi Shell!")
            return True
        else:
            print(f"    └── {YELLOW}Khong tim thay dong canh bao NODE2SHELL trong log cua Falco.{RESET}")
            print(f"        (Luu y: Dam bao container '{FALCO_CONTAINER}' dang chay tren Fedora Linux / Kernel >= 5.8).")
            return False
    except FileNotFoundError:
        print(f"[-] {RED}Khong tim thay lenh 'docker' tren may.{RESET}")
        return False
    except Exception as e:
        print(f"[-] {RED}Loi khi kiem tra log Falco: {e}{RESET}")
        return False


if __name__ == "__main__":
    sys.exit(0 if run_test() else 1)
