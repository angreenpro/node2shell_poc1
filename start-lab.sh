#!/usr/bin/env bash
set -euo pipefail
echo "[*] Khoi dong Lab CVE-2026-111497 (Tich hop 5 phien ban Node.js trong ./lab)..."
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" = "Enforcing" ]; then
    echo "[*] Phat hien Fedora SELinux Enforcing -> Cap nhat quyen doc file cau hinh cho Container..."
    chcon -Rt svirt_sandbox_file_t ./detection ./remediation ./lab 2>/dev/null || true
fi
docker compose up -d --build
echo "[+] Lab da san sang!"
echo "    - Nginx WAF        : http://localhost:8085"
echo "    - Node 20.19.5 : http://localhost:3020"
echo "    - Node 22.23.3 : http://localhost:3000 (hoac :3022)"
echo "    - Node 24.22.0 : http://localhost:3024"
echo "    - Node 22.23.4 : http://localhost:3002 (hoac :3025)"
echo "    - Node 24.22.2 : http://localhost:3026"
echo "    - Dozzle Web Log UI: http://localhost:9999"
