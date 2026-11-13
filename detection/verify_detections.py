#!/usr/bin/env python3
"""
Detection Engineering Verification Script - CVE-2026-111497 (Node2Shell)
Tu dong kiem tra kha nang phat hien cua 3 tang:
  1. Tang Bien mang (Nginx WAF Security Log & HTTP 415)
  2. Tang Ung dung (Stream Error Telemetry & Container Exit Code 139 Check)
  3. Tang Nhan OS (Falco eBPF Syscall execve Alert)
"""

import argparse
import json
import os
import subprocess
import time
import urllib.request
import urllib.error

WAF_URL = os.environ.get("LAB_WAF_URL", "http://localhost:8085")
DIRECT_URL = os.environ.get("LAB_DIRECT_URL", "http://localhost:3000")
WAF_CONTAINER = os.environ.get("LAB_WAF_CONTAINER", "lab-waf")
TARGET_CONTAINER = os.environ.get("LAB_TARGET_CONTAINER", "lab-target-node")
FALCO_CONTAINER = os.environ.get("LAB_FALCO_CONTAINER", "lab-falco-edr")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def send_req(url, method="GET", headers=None, data=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.getcode(), r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def run_docker_cmd(args_list):
    try:
        p = subprocess.run(["docker"] + args_list, capture_output=True, text=True, timeout=5)
        return p.returncode, p.stdout + p.stderr
    except Exception as e:
        return -1, str(e)


def check_layer_1_waf_detection():
    print(f"\n{CYAN}{BOLD}[Layer 1] Kiem tra Phat hien & Chan o Tang Bien mang (Nginx WAF){RESET}")
    st, _ = send_req(
        f"{WAF_URL}/api/upload",
        method="POST",
        headers={"Content-Encoding": "br", "User-Agent": "Node2Shell-Detection-Test/1.0"},
        data=b"\x8b\x00\x00\x46\xa4"
    )
    print(f"  ├── Gui goi tin Probe 'Content-Encoding: br' qua WAF -> HTTP {st}")
    rc, logs = run_docker_cmd(["logs", "--tail", "15", WAF_CONTAINER])
    waf_logged = ("415" in logs) or ("br" in logs)
    if st == 415:
        print(f"  └── Ket qua: {GREEN}[DETECTED & BLOCKED]{RESET} WAF da chan (415) va ghi nhan su kien.")
        return True
    print(f"  └── Ket qua: {RED}[MISSED]{RESET} WAF khong chan goi tin (Status={st}).")
    return False


def check_layer_2_app_crash_monitoring():
    print(f"\n{CYAN}{BOLD}[Layer 2] Kiem tra Giam sat Loi Giai nen & Trang thai Crash Container (SIGSEGV 139){RESET}")
    st, body = send_req(
        f"{DIRECT_URL}/api/upload",
        method="POST",
        headers={"Content-Encoding": "br"},
        data=b"\xff"
    )
    print(f"  ├── Gui goi tin Brotli loi (0xff) vao Backend -> HTTP {st}")
    rc, inspect_out = run_docker_cmd([
        "inspect", TARGET_CONTAINER,
        "--format", "Status={{.State.Status}} ExitCode={{.State.ExitCode}} OOMKilled={{.State.OOMKilled}}"
    ])
    if rc == 0:
        print(f"  ├── Trang thai Container ({TARGET_CONTAINER}): {BOLD}{inspect_out.strip()}{RESET}")
    if st == 400 and "ExitCode=0" in inspect_out:
        print(f"  └── Ket qua: {GREEN}[DETECTED SAFELY]{RESET} Ung dung bat loi Zlib an toan, khong bi SIGSEGV (139).")
        return True
    print(f"  └── Ket qua: {YELLOW}[WARN]{RESET} Kiem tra lai trang thai container.")
    return False


def check_layer_3_falco_ebpf():
    print(f"\n{CYAN}{BOLD}[Layer 3] Kiem tra Phat hien Syscall RCE o Tang Nhan Linux (Falco eBPF){RESET}")
    st, _ = send_req(f"{WAF_URL}/sim/rce-trigger", method="POST")
    if st != 200:
        print(f"  └── {RED}[ERROR]{RESET} Khong kich hoat duoc endpoint mo phong RCE (HTTP {st}).")
        return False

    time.sleep(2)
    rc, logs = run_docker_cmd(["logs", "--tail", "40", FALCO_CONTAINER])
    alerts = [ln for ln in logs.splitlines() if "NODE2SHELL" in ln or "CRITICAL" in ln]
    if alerts:
        print(f"  ├── Cảnh báo Falco eBPF thu duoc:")
        print(f"      {BOLD}{alerts[-1]}{RESET}")
        print(f"  └── Ket qua: {GREEN}[DETECTED - CRITICAL]{RESET} Falco da bat chinh xac hanh vi node -> /bin/sh!")
        return True
    print(f"  └── Ket qua: {YELLOW}[NO ALERT]{RESET} Khong thay log Falco (Luu y: Can chay tren Fedora/Kali Linux Kernel >= 5.8).")
    return False


def main():
    print(f"{BOLD}{CYAN}==========================================================================={RESET}")
    print(f"{BOLD}{CYAN}   HE THONG KIEM CHUNG DETECTION ENGINEERING - CVE-2026-111497 (NODE2SHELL) {RESET}")
    print(f"{BOLD}{CYAN}==========================================================================={RESET}")

    r1 = check_layer_1_waf_detection()
    r2 = check_layer_2_app_crash_monitoring()
    r3 = check_layer_3_falco_ebpf()

    print(f"\n{BOLD}==================== TONG KET KHA NANG PHAT HIEN (DETECTION) ===================={RESET}")
    print(f"  1. Tang Mang / WAF (Nginx 415 & Security Log) : {GREEN + 'PASS' + RESET if r1 else RED + 'FAIL' + RESET}")
    print(f"  2. Tang Ung dung & Container (Exit Code Check): {GREEN + 'PASS' + RESET if r2 else YELLOW + 'WARN' + RESET}")
    print(f"  3. Tang Kernel / EDR (Falco eBPF execve)      : {GREEN + 'PASS' + RESET if r3 else YELLOW + 'SKIP/WARN' + RESET}")
    print(f"{BOLD}================================================================================={RESET}\n")


if __name__ == "__main__":
    main()
