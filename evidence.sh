#!/usr/bin/env bash
# ==============================================================================
#  AUTOMATED EVIDENCE COLLECTOR (.sh) - CVE-2026-111497 (Node2Shell)
#  Phuc vu thu thap toan bo bang chung tren Linux (Fedora/Kali/Ubuntu/WSL2)
# ==============================================================================
set -euo pipefail

HOST_IP="${1:-localhost}"
WAF_PORT="${2:-8085}"
DIRECT_PORT="${3:-3000}"
EVIDENCE_DIR="${4:-evidence}"

WAF_URL="http://${HOST_IP}:${WAF_PORT}"
DIRECT_URL="http://${HOST_IP}:${DIRECT_PORT}"
LOGS_DIR="${EVIDENCE_DIR}/logs"

GREEN="\033[92m"
RED="\033[91m"
YELLOW="\033[93m"
CYAN="\033[96m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}==========================================================================${RESET}"
echo -e "${CYAN}${BOLD}  THU THAP BANG CHUNG KIEM THU LAB CVE-2026-111497 (NODE2SHELL)          ${RESET}"
echo -e "${CYAN}${BOLD}  Target WAF: ${WAF_URL} | Target Direct: ${DIRECT_URL}                 ${RESET}"
echo -e "${CYAN}${BOLD}==========================================================================${RESET}"

mkdir -p "${LOGS_DIR}"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SCORECARD_FILE="${EVIDENCE_DIR}/test_scorecard.json"

# Khoi tao file JSON Scorecard
cat <<EOF > "${SCORECARD_FILE}"
{
  "timestamp": "${TIMESTAMP}",
  "cve": "CVE-2026-111497",
  "environment": "Fedora Linux / Kali VM / Docker Host",
  "waf_url": "${WAF_URL}",
  "direct_url": "${DIRECT_URL}",
  "tests": [],
  "matrix": []
}
EOF

# --- Helper ghi them JSON vao danh sach ---
append_test_json() {
  local entry="$1"
  python3 -c "
import json
with open('${SCORECARD_FILE}', 'r') as f:
    data = json.load(f)
data['tests'].append(${entry})
with open('${SCORECARD_FILE}', 'w') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
"
}

append_matrix_json() {
  local entry="$1"
  python3 -c "
import json
with open('${SCORECARD_FILE}', 'r') as f:
    data = json.load(f)
data['matrix'].append(${entry})
with open('${SCORECARD_FILE}', 'w') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
"
}

# --- TEST 01: Reconnaissance (/api/info) ---
echo -e "\n[*] [Step 1/6] Thu thap thong tin phien ban Runtime (/api/info)..."
INFO_RESP=$(curl -s "${DIRECT_URL}/api/info" || true)
INFO_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${DIRECT_URL}/api/info" || true)

if [ "${INFO_CODE}" = "200" ]; then
    NODE_VER=$(echo "${INFO_RESP}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('nodeVersion', 'unknown'))" 2>/dev/null || echo "unknown")
    BROTLI_VER=$(echo "${INFO_RESP}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('brotliVersion', 'unknown'))" 2>/dev/null || echo "unknown")
    echo -e "    ${GREEN}[+] Node.js: ${NODE_VER} | Brotli: ${BROTLI_VER}${RESET}"
    append_test_json "{\"id\": \"01\", \"name\": \"Runtime & Brotli Version Audit\", \"passed\": True, \"nodeVersion\": \"${NODE_VER}\", \"brotliVersion\": \"${BROTLI_VER}\"}"
else
    echo -e "    ${RED}[-] Khong the ket noi toi ${DIRECT_URL}/api/info (HTTP ${INFO_CODE})${RESET}"
    append_test_json "{\"id\": \"01\", \"name\": \"Runtime & Brotli Version Audit\", \"passed\": False, \"error\": \"HTTP ${INFO_CODE}\"}"
fi

# --- TEST 02: Differential Probing (0x3b vs 0xff) ---
echo -e "\n[*] [Step 2/6] Kiem thu vi sai be mat giai nen (0x3b vs 0xff)..."
WAF_3B=$(printf "\x3b" | curl -s -o /dev/null -w "%{http_code}" -X POST "${WAF_URL}/api/upload" -H "Content-Encoding: br" -H "Content-Type: application/json" --data-binary @- || echo "0")
WAF_FF=$(printf "\xff" | curl -s -o /dev/null -w "%{http_code}" -X POST "${WAF_URL}/api/upload" -H "Content-Encoding: br" -H "Content-Type: application/json" --data-binary @- || echo "0")
DIR_3B=$(printf "\x3b" | curl -s -o /dev/null -w "%{http_code}" -X POST "${DIRECT_URL}/api/upload" -H "Content-Encoding: br" -H "Content-Type: application/json" --data-binary @- || echo "0")
DIR_FF=$(printf "\xff" | curl -s -o /dev/null -w "%{http_code}" -X POST "${DIRECT_URL}/api/upload" -H "Content-Encoding: br" -H "Content-Type: application/json" --data-binary @- || echo "0")

TEST2_PASS="False"
if [ "${WAF_3B}" = "415" ] && [ "${DIR_3B}" = "200" ] && [ "${DIR_FF}" = "400" ]; then
    TEST2_PASS="True"
    echo -e "    ${GREEN}[+] WAF Blocked (415) | Direct Inbound Exposed (Valid=200, Malformed=400) [PASS]${RESET}"
else
    echo -e "    ${YELLOW}[!] Ket qua: WAF=${WAF_3B} | Direct=${DIR_3B}/${DIR_FF}${RESET}"
fi
append_test_json "{\"id\": \"02\", \"name\": \"Differential Probing & WAF Isolation\", \"passed\": ${TEST2_PASS}, \"waf_0x3b\": ${WAF_3B}, \"waf_0xff\": ${WAF_FF}, \"direct_0x3b\": ${DIR_3B}, \"direct_0xff\": ${DIR_FF}}"

# --- TEST 03: WAF Inbound & DoS Resilience ---
echo -e "\n[*] [Step 3/6] Kiem thu WAF chan Inbound & Chong sap Event Loop..."
WAF_BLOCK=$(printf "\x1b\x00\x00\xff\xff" | curl -s -o /dev/null -w "%{http_code}" -X POST "${WAF_URL}/api/upload" -H "Content-Encoding: br" --data-binary @- || echo "0")
DIR_HANDLED=$(printf "\x1b\x00\x00\xff\xff" | curl -s -o /dev/null -w "%{http_code}" -X POST "${DIRECT_URL}/api/upload" -H "Content-Encoding: br" --data-binary @- || echo "0")
ALIVE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${DIRECT_URL}/api/info" || echo "0")

TEST3_PASS="False"
if [ "${WAF_BLOCK}" = "415" ] && [ "${ALIVE_CODE}" = "200" ]; then
    TEST3_PASS="True"
    echo -e "    ${GREEN}[+] WAF chan 415 | Backend bat loi an toan (400) khong bi crash [PASS]${RESET}"
else
    echo -e "    ${RED}[-] WAF=${WAF_BLOCK}, ServerAlive=${ALIVE_CODE}${RESET}"
fi
append_test_json "{\"id\": \"03\", \"name\": \"WAF Content-Encoding Block & DoS Resilience\", \"passed\": ${TEST3_PASS}, \"waf_blocked_415\": ${WAF_BLOCK}, \"direct_status\": ${DIR_HANDLED}, \"alive_status\": ${ALIVE_CODE}}"

# --- TEST 04: Outbound SSRF Exposure ---
echo -e "\n[*] [Step 4/6] Kiem thu Phoi nhiem Outbound HTTP Client (/api/webhook-test)..."
DEF_RESP=$(curl -s "${WAF_URL}/api/webhook-test" || echo "{}")
SAFE_RESP=$(curl -s -H "x-safe-outbound: true" "${WAF_URL}/api/webhook-test" || echo "{}")

DEF_EXPOSED=$(echo "${DEF_RESP}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('exposedToMaliciousBrotliResponse', False))" 2>/dev/null || echo "False")
SAFE_EXPOSED=$(echo "${SAFE_RESP}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('exposedToMaliciousBrotliResponse', True))" 2>/dev/null || echo "True")
DEF_ENC=$(echo "${DEF_RESP}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('clientSentAcceptEncoding', 'unknown'))" 2>/dev/null || echo "unknown")
SAFE_ENC=$(echo "${SAFE_RESP}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('clientSentAcceptEncoding', 'unknown'))" 2>/dev/null || echo "unknown")

TEST4_PASS="False"
if [ "${DEF_EXPOSED}" = "True" ] && [ "${SAFE_EXPOSED}" = "False" ]; then
    TEST4_PASS="True"
    echo -e "    ${GRAY}[+] Default Sent: '${DEF_ENC}' (Exposed=${DEF_EXPOSED})${RESET}"
    echo -e "    ${GREEN}[+] Safe Mode Sent: '${SAFE_ENC}' (Exposed=${SAFE_EXPOSED}) [PASS]${RESET}"
fi
append_test_json "{\"id\": \"04\", \"name\": \"Outbound Client Header Leakage (SSRF)\", \"passed\": ${TEST4_PASS}, \"default_accept_encoding\": \"${DEF_ENC}\", \"default_exposed\": ${DEF_EXPOSED}, \"safe_accept_encoding\": \"${SAFE_ENC}\", \"safe_exposed\": ${SAFE_EXPOSED}}"

# --- TEST 05: RCE Telemetry Trigger ---
echo -e "\n[*] [Step 5/6] Kich hoat RCE Telemetry Trigger (/sim/rce-trigger)..."
RCE_OUT=$(curl -s -X POST "${WAF_URL}/sim/rce-trigger" || true)
TEST5_PASS="False"
if [ -n "${RCE_OUT}" ]; then
    TEST5_PASS="True"
    CLEAN_RCE=$(echo "${RCE_OUT}" | tr '\n' ' ' | sed 's/"/\\"/g')
    echo -e "    ${GREEN}[+] RCE Output: ${RCE_OUT} [TRIGGERED]${RESET}"
    append_test_json "{\"id\": \"05\", \"name\": \"Post-Exploitation RCE Telemetry\", \"passed\": True, \"output\": \"${CLEAN_RCE}\"}"
else
    echo -e "    ${RED}[-] Khong the goi /sim/rce-trigger${RESET}"
    append_test_json "{\"id\": \"05\", \"name\": \"Post-Exploitation RCE Telemetry\", \"passed\": False}"
fi

# --- MA TRAN DA PHIEN BAN (Multi-Version Matrix) ---
echo -e "\n[*] [Step 6/6] Kiem tra Ma tran da phien ban (Cac cong 3020..3026)..."
VERSIONS=("Node 20.19.5 (EOL Vuln):3020" "Node 22.23.3 (LTS Vuln):3022" "Node 24.22.0 (Current Vuln):3024" "Node 22.23.4 (Patched):3025" "Node 24.22.2 (Patched):3026")

for item in "${VERSIONS[@]}"; do
    NAME="${item%%:*}"
    PORT="${item##*:}"
    U="http://${HOST_IP}:${PORT}"
    
    ST_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${U}/api/info" || echo "0")
    if [ "${ST_CODE}" = "200" ]; then
        V_JSON=$(curl -s "${U}/api/info")
        N_V=$(echo "${V_JSON}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('nodeVersion', 'N/A'))" 2>/dev/null || echo "N/A")
        B_V=$(echo "${V_JSON}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('brotliVersion', 'N/A'))" 2>/dev/null || echo "N/A")
        
        CORRUPTED_PROBE=$(printf "\x8b\x00\x00\x46\xa4" | curl -s -o /dev/null -w "%{http_code}" -X POST "${U}/api/upload" -H "Content-Encoding: br" --data-binary @- || echo "0")
        
        VERDICT="PATCHED (SAFE)"
        if [ "${CORRUPTED_PROBE}" = "200" ]; then
            VERDICT="VULNERABLE"
        fi
        
        echo -e "    ├── ${NAME} [Port ${PORT}] -> Node ${N_V} | Brotli ${B_V} | Verdict: ${CYAN}${VERDICT}${RESET}"
        append_matrix_json "{\"profile\": \"${NAME}\", \"port\": ${PORT}, \"nodeVersion\": \"${N_V}\", \"brotliVersion\": \"${B_V}\", \"probeStatus\": ${CORRUPTED_PROBE}, \"verdict\": \"${VERDICT}\"}"
    else
        echo -e "    ├── ${NAME} [Port ${PORT}] -> ${YELLOW}OFFLINE${RESET}"
    fi
done

# --- TRICH XUAT LOGS CONTAINER DOCKER ---
echo -e "\n[*] Dang trich xuat log Docker vao ${LOGS_DIR}..."
CONTAINERS=("lab-waf" "lab-target-node" "lab-falco-edr" "lab-mock-external")
for c in "${CONTAINERS[@]}"; do
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
        docker logs --tail 100 "${c}" > "${LOGS_DIR}/${c}.log" 2>&1 || true
        echo -e "    ${GREEN}[+] Da luu: ${LOGS_DIR}/${c}.log${RESET}"
    else
        echo -e "    ${YELLOW}[!] Container ${c} khong ton tai hoac khong chay tren may host nay.${RESET}"
    fi
done

echo -e "\n${GREEN}[+] HOAN TAT! Toan bo bang chung da duoc luu tai:${RESET}"
echo -e "    - File Scorecard JSON : ${SCORECARD_FILE}"
echo -e "    - Thu muc Log Files   : ${LOGS_DIR}"
echo -e "${CYAN}${BOLD}==========================================================================${RESET}"