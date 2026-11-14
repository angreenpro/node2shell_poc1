#!/usr/bin/env python3
import subprocess
import time
import sys
from common import DIRECT_APP_URL, FALCO_CONTAINER, GREEN, RED, YELLOW, BOLD, RESET, http_request, print_banner

def run_test(base_url: str = DIRECT_APP_URL) -> bool:
    print_banner("TEST 05: KIEM THU PHAT HIEN RCE (NODE2SHELL) TREN FALCO eBPF")
    print(f"[*] Buoc 1: Kich hoat gia lap hanh vi tien trinh 'node' sinh ra '/bin/sh'...")
    status, _, body = http_request(f"{base_url}/sim/rce-trigger", method="POST")
    if status != 200:
        print(f"[-] {RED}Khong the kich hoat /sim/rce-trigger (HTTP {status}){RESET}")
        return False
    print(f"    └── Phan hoi tu Target App: {body.strip().replace(chr(10), ' | ')}")

    print(f"\n[*] Buoc 2: Doi 2 giay de Falco eBPF thu thap su kien syscall 'execve' tu Kernel...")
    time.sleep(2)

    print(f"[*] Buoc 3: Truy van log canh bao tu Falco eBPF (Fedora Systemd Journal & Docker)...")
    logs = ""
    for cmd in [
        ["journalctl", "-u", "falco-modern-bpf.service", "-u", "falco.service", "-n", "50", "--no-pager"],
        ["docker", "logs", "--tail", "50", FALCO_CONTAINER]
    ]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            logs += "\n" + p.stdout + p.stderr
        except Exception:
            pass

    alerts = [line for line in logs.splitlines() if "NODE2SHELL" in line or "CRITICAL" in line]
    if alerts:
        print(f"    └── {GREEN}Tim thay canh bao tu Falco EDR:{RESET}")
        print(f"        {BOLD}{alerts[-1]}{RESET}")
        print(f"\n[+] KET LUAN: {GREEN}{BOLD}[PASS]{RESET} He thong EDR/eBPF da bat chinh xac hanh vi Node.js goi Shell!")
        return True
    else:
        print(f"    └── {YELLOW}Khong tim thay dong canh bao NODE2SHELL trong log cua Falco.{RESET}")
        return False

if __name__ == "__main__":
    sys.exit(0 if run_test() else 1)
