#!/usr/bin/env bash
set -u
echo "[*] Dang tat va don dep toan bo container Lab CVE-2026-111497..."
docker compose down -v --remove-orphans 2>/dev/null || true
docker compose -f lab/docker-compose.yml down -v --remove-orphans 2>/dev/null || true
docker compose -f remediation/docker-compose-patched.yml -p node2shell-remediated down -v --remove-orphans 2>/dev/null || true
echo "[+] Da don dep hoan tat."
