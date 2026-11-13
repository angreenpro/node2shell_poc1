#!/usr/bin/env bash
# ==============================================================================
# AUTOMATED REMEDIATION DEPLOYMENT SCRIPT - CVE-2026-111497 (Node2Shell)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=========================================================================="
echo "  BAT DAU QUY TRINH KHAC PHUC & GIA CO (REMEDIATION) - CVE-2026-111497"
echo "=========================================================================="

# Tu dong kiem tra neu dang chay tren Fedora Linux (SELinux Enforcing)
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
    echo "[*] Phat hien SELinux Enforcing tren Fedora: Dang cap nhat nhan SELinux cho thu muc configs..."
    chcon -Rt svirt_sandbox_file_t "$REM_DIR/configs" 2>/dev/null || true
fi

echo "[*] Buoc 1: Build va khoi chay cum Container Da Va (Patched Node 22.23.4 + Hardened WAF)..."
cd "$REM_DIR"
docker compose -f docker-compose-patched.yml -p node2shell-remediated up -d --build

echo "[*] Buoc 2: Doi 3 giay de cac dich vu khoi dong hoan tat..."
sleep 3

echo "[*] Buoc 3: Chay kiem thu nghiem thu tu dong (verify_remediation.py)..."
python3 "$REM_DIR/tests/verify_remediation.py"
