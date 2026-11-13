#!/usr/bin/env bash
# ==============================================================================
#  PURPLE TEAM LAB LAUNCHER & TEST RUNNER (.sh) - CVE-2026-111497 (Node2Shell)
#  Ho tro: Fedora Linux (Native) & Windows WSL2
# ==============================================================================
set -u

WAF_URL="${LAB_WAF_URL:-http://localhost:8080}"
DIRECT_URL="${LAB_DIRECT_URL:-http://localhost:3000}"
FALCO_CONTAINER="${LAB_FALCO_CONTAINER:-lab-falco-edr}"

GREEN="\033[92m"
RED="\033[91m"
YELLOW="\033[93m"
CYAN="\033[96m"
BOLD="\033[1m"
RESET="\033[0m"

banner() {
    echo -e "\n${CYAN}${BOLD}==========================================================================${RESET}"
    echo -e "${CYAN}${BOLD}  $1${RESET}"
    echo -e "${CYAN}${BOLD}==========================================================================${RESET}"
}

test_01_recon() {
    banner "[TEST 01] KIEM TRA PHIEN BAN BINARY NODE.JS & C++ BROTLI"
    echo -e "[*] Goi lenh: curl -s ${DIRECT_URL}/api/info"
    resp=$(curl -s -w "\n%{http_code}" "${DIRECT_URL}/api/info" || true)
    code=$(echo "$resp" | tail -n1)
    body=$(echo "$resp" | sed '$d')

    if [ "$code" = "200" ]; then
        echo -e "$body"
        echo -e "${GREEN}[PASS] Da thu thap thong tin phien ban Runtime thanh cong.${RESET}"
    else
        echo -e "${RED}[FAIL] Khong the ket noi toi ${DIRECT_URL}/api/info (HTTP $code)${RESET}"
    fi
}

test_02_differential() {
    banner "[TEST 02] KIEM THU VI SAI BE MAT GIAI NEN (0x3b vs 0xff)"
    echo -e "${BOLD}1. Gui qua Nginx WAF (${WAF_URL}/api/upload):${RESET}"
    w_valid=$(printf "\x3b" | curl -s -o /dev/null -w "%{http_code}" -X POST "${WAF_URL}/api/upload" -H "Content-Encoding: br" -H "Content-Type: application/json" --data-binary @-)
    w_mal=$(printf "\xff" | curl -s -o /dev/null -w "%{http_code}" -X POST "${WAF_URL}/api/upload" -H "Content-Encoding: br" -H "Content-Type: application/json" --data-binary @-)
    echo -e "   ├── Goi 0x3b (Valid Empty Brotli) : HTTP ${w_valid}"
    echo -e "   └── Goi 0xff (Malformed Brotli)   : HTTP ${w_mal}"

    echo -e "\n${BOLD}2. Gui truc tiep vao Backend (${DIRECT_URL}/api/upload):${RESET}"
    d_valid=$(printf "\x3b" | curl -s -o /dev/null -w "%{http_code}" -X POST "${DIRECT_URL}/api/upload" -H "Content-Encoding: br" -H "Content-Type: application/json" --data-binary @-)
    d_mal=$(printf "\xff" | curl -s -o /dev/null -w "%{http_code}" -X POST "${DIRECT_URL}/api/upload" -H "Content-Encoding: br" -H "Content-Type: application/json" --data-binary @-)
    echo -e "   ├── Goi 0x3b (Valid Empty Brotli) : HTTP ${d_valid} (Mong doi: 200)"
    echo -e "   └── Goi 0xff (Malformed Brotli)   : HTTP ${d_mal} (Mong doi: 400)"
}

test_03_waf_and_dos() {
    banner "[TEST 03] KIEM THU CHOT CHAN WAF (HTTP 415) & CHONG SAP STREAM"
    for enc in "br" "BR" "gzip, br"; do
        code=$(printf "\x3b" | curl -s -o /dev/null -w "%{http_code}" -X POST "${WAF_URL}/api/upload" -H "Content-Encoding: ${enc}" --data-binary @-)
        echo -e "   ├── WAF Test Header 'Content-Encoding: ${enc}' -> HTTP ${code}"
    done

    echo -e "\n[*] Kiem tra Stream Error Handling tren Backend (${DIRECT_URL}/api/upload)..."
    err_code=$(printf "\x1b\x00\x00\xff\xff" | curl -s -o /dev/null -w "%{http_code}" -X POST "${DIRECT_URL}/api/upload" -H "Content-Encoding: br" --data-binary @-)
    alive_code=$(curl -s -o /dev/null -w "%{http_code}" "${DIRECT_URL}/api/info")
    echo -e "   ├── Gui luong byte hong -> HTTP ${err_code}"
    echo -e "   └── Kiem tra trang thai song cua Server (/api/info) -> HTTP ${alive_code}"
}

test_04_outbound() {
    banner "[TEST 04] KIEM THU PHOI NHIEM CHIEU RA (OUTBOUND FETCH CLIENT)"
    echo -e "${BOLD}[Mac dinh - Chua loc 'br']:${RESET}"
    curl -s "${WAF_URL}/api/webhook-test"
    echo -e "\n${BOLD}[An toan - Da bat co x-safe-outbound: true]:${RESET}"
    curl -s -H "x-safe-outbound: true" "${WAF_URL}/api/webhook-test"
}

test_05_edr_falco() {
    banner "[TEST 05] KICH HOAT GIA LAP RCE TELEMETRY & KIEM TRA FALCO eBPF"
    curl -s -X POST "${WAF_URL}/sim/rce-trigger"
    echo -e "\n[*] Doi 2 giay va doc log tu container ${FALCO_CONTAINER}..."
    sleep 2
    if command -v docker >/dev/null 2>&1; then
        docker logs --tail 25 "${FALCO_CONTAINER}" 2>&1 | grep -E "NODE2SHELL|CRITICAL" || echo -e "${YELLOW}[!] Khong tim thay log CRITICAL (Kiem tra xem Falco co dang chay tren Fedora Kernel >= 5.8 khong).${RESET}"
    fi
}

run_python_suite() {
    banner "CHAY BO PYTHON TEST SUITE (run_all_tests.py)"
    python3 run_all_tests.py "$@"
}

run_all_curl() {
    test_01_recon
    test_02_differential
    test_03_waf_and_dos
    test_04_outbound
    test_05_edr_falco
}

# Neu truyen tham so (1..5, all, py), chay truc tiep khong can menu
if [ $# -gt 0 ]; then
    case "$1" in
        1|01) test_01_recon ;;
        2|02) test_02_differential ;;
        3|03) test_03_waf_and_dos ;;
        4|04) test_04_outbound ;;
        5|05) test_05_edr_falco ;;
        py) shift; run_python_suite "$@" ;;
        all|*) run_all_curl ;;
    esac
    exit 0
fi

# Menu tuong tac
while true; do
    echo -e "\n${CYAN}${BOLD}================ MENU KICH HOAT KIEM THU NODE2SHELL ================${RESET}"
    echo "  1) Chay Test 01: Kiem tra phien ban Node.js & Brotli (curl)"
    echo "  2) Chay Test 02: Kiem thu vi sai 0x3b vs 0xff (curl)"
    echo "  3) Chay Test 03: Kiem thu WAF 415 & Chong sap Stream (curl)"
    echo "  4) Chay Test 04: Kiem thu Outbound Fetch Header (curl)"
    echo "  5) Chay Test 05: Kich hoat RCE Telemetry & Check Falco Log"
    echo "  a) Chay TOAN BO 5 bai test bang lenh curl"
    echo "  p) Chay Python Master Test Suite (run_all_tests.py)"
    echo "  d) Khoi dong Lab Docker (docker compose up -d)"
    echo "  q) Thoat"
    echo -e "${CYAN}====================================================================${RESET}"
    read -r -p "Chon thao tac [1-5, a, p, d, q]: " choice
    case "$choice" in
        1) test_01_recon ;;
        2) test_02_differential ;;
        3) test_03_waf_and_dos ;;
        4) test_04_outbound ;;
        5) test_05_edr_falco ;;
        a|A) run_all_curl ;;
        p|P) run_python_suite ;;
        d|D) docker compose up -d ;;
        q|Q) exit 0 ;;
        *) echo -e "${YELLOW}Lua chon khong hop le!${RESET}" ;;
    esac
done
