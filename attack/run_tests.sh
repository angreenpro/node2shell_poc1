#!/usr/bin/env bash
# Script Bash chay nhanh bo kiem thu Purple Team CVE-2026-111497 tren Fedora / WSL2
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================================="
echo "  KHOI CHAY BO KIEM THU CVE-2026-111497 (NODE2SHELL LAB)"
echo "  Moi truong OS: $(uname -s) | Kernel: $(uname -r)"
echo "=========================================================================="

# Tu dong phat hien neu dang chay trong WSL2 de goi y co --skip-edr neu can
if grep -qi "microsoft" /proc/version 2>/dev/null; then
    echo "[!] Phat hien moi truong Windows WSL2."
    echo "    Neu container Falco eBPF khong chay tren WSL2, ban co the dung: ./run_tests.sh --skip-edr"
fi

python3 run_all_tests.py "$@"
