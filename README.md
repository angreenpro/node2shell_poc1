# 🛡️ CVE-2026-111497 ("Node2Shell") — Full-Stack Purple Team & Multi-Version Lab

[![CVE](https://img.shields.io/badge/CVE-2026--111497-critical?style=flat-square&color=b91c1c)](https://nvd.nist.gov/vuln/detail/CVE-2026-111497)
[![CVSS v4](https://img.shields.io/badge/CVSS_v4-9.2_Critical-red?style=flat-square)]()
[![CWE](https://img.shields.io/badge/CWE-787_%7C_252-orange?style=flat-square)]()
[![CISA KEV](https://img.shields.io/badge/CISA-KEV_Catalog-darkred?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Lab-Fedora_44_KDE_%7C_Windows_11_%7C_Kali_WSL2-blue?style=flat-square)]()

Kho mã nguồn này cung cấp môi trường thực nghiệm **Purple Team (Red Team Validation & Blue Team Detection Engineering)** hoàn chỉnh cho lỗ hổng **CVE-2026-111497 ("Node2Shell")** — lỗi ghi tràn bộ nhớ ngoài phạm vi (*Out-of-Bounds Write* - `CWE-787`) kết hợp lỗi không kiểm tra giá trị trả về (*Unchecked Return Value* - `CWE-252`) trong thư viện C/C++ Google Brotli (`1.0.3` – `1.2.0`) được biên dịch tĩnh bên trong mô-đun `node:zlib` của Node.js.

> **⚠️ Tuyên bố An toàn & Đạo đức (Safety & Ethics Notice):**  
> Môi trường Lab này sử dụng kỹ thuật **Dò quét Vi sai Toán học (Differential Black-box Probing)** với các gói tin đối chứng an toàn (`0x3b`, `0xff`, và chuỗi thăm dò chuyển khối `8b000046a4...`) kết hợp giả lập hành vi hậu khai thác có kiểm soát. Kho mã nguồn tuyệt đối không phát tán shellcode phá hủy và chỉ được phép sử dụng trên hạ tầng cục bộ (`localhost`) hoặc mạng ảo cô lập do bạn sở hữu.

---

## 📑 Mục lục

1. [Tổng quan Cơ chế Lỗ hổng & Bề mặt Tấn công](#1-tổng-quan-cơ-chế-lỗ-hổng--bề-mặt-tấn-công)
2. [Sơ đồ Kiến trúc Mạng & Ánh xạ Cổng (Port Mapping)](#2-sơ-đồ-kiến-trúc-mạng--ánh-xạ-cổng-port-mapping)
3. [Cấu trúc Thư mục Dự án (`node2shell_poc1`)](#3-cấu-trúc-thư-mục-dự-án-node2shell_poc1)
4. [Hướng dẫn Khởi chạy Môi trường Lab](#4-hướng-dẫn-khởi-chạy-môi-trường-lab)
5. [Hướng dẫn Chạy Bộ Script Kiểm thử Tấn công (`attack/`)](#5-hướng-dẫn-chạy-bộ-script-kiểm-thử-tấn-công-attack)
6. [Hướng dẫn Chạy Script Giám sát (`detection/`) & Khắc phục (`remediation/`)](#6-hướng-dẫn-chạy-script-giám-sát-detection--khắc-phục-remediation)
7. [Thu thập Bằng chứng Tự động (`evidence.sh`) & Dọn dẹp Lab](#7-thu-thập-bằng-chứng-tự-động-evidencesh--dọn-dẹp-lab)
8. [Xử lý Sự cố Thường gặp (Troubleshooting)](#8-xử-lý-sự-cố-thường-gặp-troubleshooting)

---

## 1. Tổng quan Cơ chế Lỗ hổng & Bề mặt Tấn công

Khi giải nén dữ liệu nén Brotli theo luồng (*Streaming State Machine*), nếu bộ giải nén gặp một lệnh chuyển khối (**Block Switch**) bị làm sai lệch cấu trúc ngay tại ranh giới gói tin (chunk), hàm xử lý nội bộ lại trả về trạng thái `BROTLI_DECODER_NEEDS_MORE_INPUT` thay vì trả về lỗi định dạng `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH`. Ở các gói tin tiếp theo, dữ liệu mới liên tục bị nối thêm (*append*) vượt quá bộ đệm nội bộ 8-byte, tràn trực tiếp sang vùng nhớ **Heap** của tiến trình `node`, dẫn tới sập dịch vụ (`SIGSEGV` - Exit Code `139`) hoặc Thực thi mã từ xa (**RCE**).

Môi trường Lab mô phỏng đầy đủ **2 hướng phơi nhiễm chính** và **5 nhánh phiên bản Node.js**:
* **Hướng 1 — Chiều vào (Inbound Request Decompression):** Người dùng gửi HTTP Request mang header `Content-Encoding: br` đi qua (hoặc bỏ qua) tầng Nginx WAF vào thẳng endpoint `/api/upload` sử dụng `node:zlib`.
* **Hướng 2 — Chiều ra (Outbound HTTP Client / SSRF Exposure):** Ứng dụng dùng hàm `fetch()` (hoặc `axios` / `undici`) gọi tới máy chủ bên ngoài (`/api/webhook-test`). Vì WAF chỉ kiểm tra chiều vào và `fetch()` mặc định đính kèm header `Accept-Encoding: br, gzip, deflate`, máy chủ bên ngoài có thể trả về luồng Brotli độc hại để kích hoạt lỗi từ bên trong.

---

## 2. Sơ đồ Kiến trúc Mạng & Ánh xạ Cổng (Port Mapping)

```text
[ Attacker: Kali VM / Fedora Host (attack/*.py & evidence.sh) ]
       │
       ├──► (Port 8085) ──► [ lab-waf (Nginx WAF) ] ──► Chặn "Content-Encoding: br" (HTTP 415)
       │                           │
       │                           ▼ (Mạng nội bộ cyber-lab-net: http://app-vulnerable:3000)
       ├──► (Port 3000 / 3022) ──► [ lab-target-node (Node v22.23.3 - LTS Vuln, Brotli 1.1.0) ]
       │                                  │
       │                                  ├──► Outbound fetch() ──► [ lab-mock-external (:4000) ]
       │                                  └──► Syscall execve   ──► [ Falco eBPF EDR (Kernel Probe) ]
       │
       ├──► (Port 3020) ─────────► [ lab-node20-19-5 (Node v20.19.5 - EOL Vuln, Brotli 1.0.9) ]
       ├──► (Port 3024) ─────────► [ lab-node24-22-0 (Node v24.22.0 - Current Vuln, Brotli 1.1.0) ]
       ├──► (Port 3002 / 3025) ──► [ lab-node22-23-4 (Node v22.23.4 - LTS PATCHED, Brotli 1.1.1) ]
       ├──► (Port 3026) ─────────► [ lab-node24-22-2 (Node v24.22.2 - Current PATCHED, Brotli 1.2.1) ]
       └──► (Port 9999) ─────────► [ lab-dozzle-ui (Giao diện Web theo dõi Container Logs trực tiếp) ]
```

### Bảng Tổng hợp Cổng Dịch vụ (Ports)

| Cổng Host | Tên Container | Thư mục Nguồn | Phiên bản Node & `libbrotli` | Trạng thái / Vai trò |
| :---: | :--- | :--- | :--- | :--- |
| **`:8085`** | `lab-waf` | `detection/nginx_waf.conf` | Nginx Alpine | **Edge WAF** (Chặn `Content-Encoding: br` $\rightarrow$ `HTTP 415`) |
| **`:3000`** & **`:3022`** | `lab-target-node` | `lab/node-22.23.3/` | Node `v22.23.3` \| Brotli `1.1.0` | **VULNERABLE** — Target chính đứng sau WAF & Cổng Direct |
| **`:3020`** | `lab-node20-19-5` | `lab/node-20.19.5/` | Node `v20.19.5` \| Brotli `1.0.9` | **VULNERABLE (EOL)** — Nhánh 20.x ngừng hỗ trợ, không có bản vá |
| **`:3024`** | `lab-node24-22-0` | `lab/node-24.22.0/` | Node `v24.22.0` \| Brotli `1.1.0` | **VULNERABLE** — Nhánh 24.x Current chưa vá |
| **`:3002`** & **`:3025`** | `lab-node22-23-4` | `lab/node-22.23.4/` | Node `v22.23.4` \| Brotli `1.1.1` | **PATCHED (SAFE)** — Bản đối chứng LTS đã vá lỗi |
| **`:3026`** | `lab-node24-22-2` | `lab/node-24.22.2/` | Node `v24.22.2` \| Brotli `1.2.1` | **PATCHED (SAFE)** — Bản đối chứng Current đã vá hoàn chỉnh |
| **`:4000`** *(Nội bộ)* | `lab-mock-external`| `lab/mock-external/` | Node `v22` | Máy chủ bên ngoài kiểm tra rò rỉ `Accept-Encoding: br` chiều ra |
| **`:9999`** | `lab-dozzle-ui` | Image `amir20/dozzle` | Dozzle Latest | Giao diện Web xem trực tiếp log của toàn bộ Container |

---

## 3. Cấu trúc Thư mục Dự án (`node2shell_poc1`)

```text
node2shell_poc1/
├── docker-compose.yml                        # File Compose chính: Khởi chạy WAF + 5 Node Versions + Falco + Dozzle
├── start-lab.sh / start-lab.ps1              # Script khởi chạy Lab trên Linux (Fedora 44 / Kali VM)
├── cleanup-lab.sh / cleanup-lab.ps1          # Script dọn dẹp toàn bộ container và mạng ảo
├── evidence.sh                               # Script tự động chạy kiểm thử toàn diện & gom bằng chứng vào ./evidence/
├── README.md                                 
│
├── lab/                                      # 5 PHIÊN BẢN NODE.JS CÔ LẬP ĐỘC LẬP
│   ├── docker-compose.yml                    # Compose chạy riêng cụm 5 phiên bản Node.js + Mock External
│   ├── compare_versions_matrix.py            # Script Python đối chứng đồng loạt 5 phiên bản (3020..3026)
│   ├── node-20.19.5/                         # Nhánh 20.x EOL - Dockerfile, .env, server.js, package.json
│   ├── node-22.23.3/                         # Nhánh 22.x LTS - Target chính, có đầy đủ 4 route + RCE trigger
│   ├── node-24.22.0/                         # Nhánh 24.x Current - libbrotli 1.1.0
│   ├── node-22.23.4/                         # Nhánh 22.x LTS - libbrotli 1.1.1
│   ├── node-24.22.2/                         # Nhánh 24.x Current - libbrotli 1.2.1
│   └── mock-external/                        # Máy chủ giả lập kiểm tra Outbound HTTP Client (Port 4000)
│
├── attack/                                   # BỘ SCRIPT KIỂM THỬ TẤN CÔNG (0-DEPENDENCY PYTHON)
│   ├── common.py                             # Module HTTP dùng chung (chỉ dùng urllib chuẩn của Python)
│   ├── test_01_recon_version.py              # Test 01: Rà soát phiên bản Runtime Binary & C++ libbrotli (/api/info)
│   ├── test_02_differential_probe.py         # Test 02: Dò quét vi sai hộp đen (Gói 0x3b hợp lệ vs 0xff lỗi)
│   ├── test_03_inbound_waf_and_dos.py        # Test 03: Kiểm thử lách WAF (HTTP 415) & Chống sập Event Loop
│   ├── test_04_outbound_ssrf_client.py       # Test 04: Kiểm thử phơi nhiễm Outbound fetch() Accept-Encoding: br
│   ├── test_05_edr_rce_telemetry.py          # Test 05: Kích hoạt RCE (/sim/rce-trigger) & Truy vấn cảnh báo Falco eBPF
│   ├── run_all_tests.py                      # Master Test Runner chạy từ Test 01 -> Test 05
│   └── run_lab_tests.sh / .ps1               # Menu tương tác CLI chọn chạy từng bài test bằng curl / PowerShell
│
├── detection/                                # PHÁT HIỆN & GIÁM SÁT ĐA TẦNG (BLUE TEAM / SOC)
│   ├── falco_rules.yaml                      # Luật Kernel eBPF bắt syscall execve khi tiến trình `node` mở `/bin/sh`
│   ├── suricata.rules                        # Luật IDS bắt luồng Brotli Probe (8b 00 00 46 a4) & gói dò quét 0xff
│   ├── auditd.rules                          # Luật Linux Auditd giám sát thực thi shell & truy cập file nhạy cảm
│   ├── nginx_waf.conf                        # Cấu hình Nginx WAF chặn Content-Encoding: br & ghi log an ninh
│   ├── verify_detections.py                  # Script tự động kiểm chứng 3 tầng phát hiện (WAF, Crash 139, Falco)
│   └── PLAYBOOK.md                           # Quy trình phản ứng sự cố 4 bước chuẩn SOC
│
├── remediation/                              # KHẮC PHỤC, GIA CỐ & NGHIỆM THU A/B
│   ├── REMEDIATION_SUMMARY.md                
│   ├── docker-compose-patched.yml            # Cụm Docker đã gia cố (Non-root USER node, Read-only FS, Cap Drop ALL)
│   ├── configs/                              
│   ├── patches/
│   │   └── apply_remediation.sh              # Script tự động triển khai bản vá và chạy nghiệm thu
│   └── tests/
│       ├── verify_remediation.py             # Kiểm thử lại (Re-testing) 5 tiêu chí an toàn sau khi vá
│       └── compare_labs.py                   # Đối chứng trực tiếp A/B giữa Trước khi vá (:3000) và Sau khi vá (:3002)
│
└── evidence/                                 # BẰNG CHỨNG THỰC NGHIỆM & LOGS THU THẬP
    ├── test_scorecard.json                   # Kết quả chấm điểm tự động 5 bài test & Ma trận 5 phiên bản Node.js
    └── logs/                                 # Lưu trữ log trích xuất từ lab-waf, lab-target-node, lab-falco-edr...
```

---

## 4. Hướng dẫn Khởi chạy Môi trường Lab

Toàn bộ các script Python trong dự án được viết bằng **thư viện chuẩn 100% (`urllib`, `json`, `subprocess`)**, không cần cài đặt thêm bất kỳ gói `pip` bên ngoài nào.

### 4.1. Khởi chạy trên Fedora (hoặc Kali Linux)

```bash
# 1. Cấp quyền thực thi cho toàn bộ các script trong dự án
chmod +x *.sh attack/*.sh attack/*.py lab/*.py detection/*.py remediation/patches/*.sh remediation/tests/*.py

# 2. Khởi chạy toàn bộ cụm Lab (Script tự động xử lý nhãn SELinux trên Fedora)
./start-lab.sh
```

> **Cấu hình Falco eBPF trên Fedora 44 KDE (Kernel 6.x / 7.2):**  
> Nếu bạn cài đặt Falco trực tiếp trên máy chủ Fedora (`systemd`) để bắt sự kiện nhân ở Bài Test 05, hãy nạp rule phát hiện Node2Shell bằng lệnh:
> ```bash
> sudo cp ./detection/falco_rules.yaml /etc/falco/rules.d/node2shell_rules.yaml
> sudo systemctl enable --now falco-modern-bpf.service
> ```

### 4.2. Khởi chạy trên Windows 11 (PowerShell + Docker Desktop)

Để hiển thị đúng tiếng Việt có dấu trên Windows PowerShell mà không bị lỗi bảng mã UTF-8:

```powershell
# 1. Chuyển bảng mã Console của PowerShell sang UTF-8
chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 2. Khởi chạy toàn bộ cụm Container Lab
.\start-lab.ps1
```

### 4.3. Kiểm tra trạng thái các Container sau khi bật

```bash
docker ps
```
Bạn cũng có thể mở trình duyệt truy cập **`http://localhost:9999`** (Dozzle Web UI) để xem trực tiếp log thời gian thực của toàn bộ các container.

---

## 5. Hướng dẫn Chạy Bộ Script Kiểm thử Tấn công (`attack/`)

> **Lưu ý về cổng WAF (`8085`):** Trong `docker-compose.yml`, Nginx WAF được ánh xạ ra cổng **`8085`** của máy chủ để tránh xung đột cổng `8080`. Khi chạy các script trong `attack/`, bạn truyền thêm biến `LAB_WAF_URL="http://localhost:8085"`.

### 5.1. Chạy Tổng hợp Toàn bộ 5 Kịch bản Kiểm thử (`run_all_tests.py`)

* **Trên Fedora 44 KDE (Chạy đầy đủ cả 5 bài test từ Test 01 $\rightarrow$ Test 05 kèm Falco eBPF):**
  ```bash
  sudo LAB_WAF_URL="http://localhost:8085" LAB_DIRECT_URL="http://localhost:3000" \
    python3 attack/run_all_tests.py -o evidence/test_scorecard.json
  ```

* **Trên Windows / Kali WSL2 (Nếu muốn bỏ qua kiểm tra Kernel eBPF bằng cờ `--skip-edr`):**
  ```bash
  LAB_WAF_URL="http://localhost:8085" LAB_DIRECT_URL="http://localhost:3000" \
    python3 attack/run_all_tests.py --skip-edr -o evidence/test_scorecard.json
  ```

### 5.2. Chạy Lẻ Từng Bài Kiểm thử (Test 01 $\rightarrow$ Test 05)

Bạn có thể chạy độc lập từng kịch bản để phân tích và chụp ảnh màn hình báo cáo:

```bash
# Test 01: Rà soát phiên bản Runtime Binary & thư viện C++ libbrotli (/api/info)
python3 attack/test_01_recon_version.py http://localhost:3000

# Test 02: Kiểm thử vi sai bề mặt giải nén (Gói 0x3b rỗng hợp lệ vs 0xff lỗi định dạng)
LAB_WAF_URL="http://localhost:8085" LAB_DIRECT_URL="http://localhost:3000" \
  python3 attack/test_02_differential_probe.py

# Test 03: Kiểm thử chốt chặn WAF (HTTP 415 với br/BR/gzip,br) & Chống sập Stream Error
LAB_WAF_URL="http://localhost:8085" LAB_DIRECT_URL="http://localhost:3000" \
  python3 attack/test_03_inbound_waf_and_dos.py

# Test 04: Kiểm thử phơi nhiễm HTTP Client chiều ra (Outbound fetch Accept-Encoding: br)
LAB_WAF_URL="http://localhost:8085" \
  python3 attack/test_04_outbound_ssrf_client.py

# Test 05: Kích hoạt RCE giả lập (/sim/rce-trigger) & Kiểm tra cảnh báo Falco eBPF
sudo LAB_WAF_URL="http://localhost:8085" LAB_DIRECT_URL="http://localhost:3000" \
  python3 attack/test_05_edr_rce_telemetry.py
```

### 5.3. Chạy Menu Tương tác CLI (`run_lab_tests.sh` / `run_lab_tests.ps1`)

Nếu muốn chọn từng kịch bản qua giao diện Menu số (`1`–`5`, `a`, `p`):

* **Trên Linux:**
  ```bash
  LAB_WAF_URL="http://localhost:8085" ./attack/run_lab_tests.sh
  ```
* **Trên Windows PowerShell:**
  ```powershell
  .\attack\run_lab_tests.ps1 -WafUrl "http://localhost:8085"
  ```

---

## 6. Hướng dẫn Chạy Script Giám sát (`detection/`) & Khắc phục (`remediation/`)

### 6.1. Đối chứng Ma trận 5 Phiên bản Node.js (`lab/compare_versions_matrix.py`)

Kịch bản này gửi đồng loạt 3 mẫu gói tin (`0x3b`, `0xff`, và chuỗi **CVE Block-Switch Probe `8b000046a4...`**) tới cả 5 cổng phiên bản (`3020`, `3022`, `3024`, `3025`, `3026`) để chứng minh sự khác biệt giữa các bản lỗi và bản đã vá:

```bash
python3 lab/compare_versions_matrix.py --host localhost -o evidence/version_matrix_report.json
```

**Kết quả hiển thị trên Terminal:**
```text
Phien ban / Profile      | Node Ver   | libbrotli  | Valid(3b)  | Mal(ff)    | Probe(CVE)  | Ket luan (Verdict)
------------------------------------------------------------------------------------------------------
Node 20.19.5 (Vuln)      | v20.19.5   | 1.0.9      | HTTP 200   | HTTP 400   | HTTP 200    | VULNERABLE
Node 22.23.3 (Vuln)      | v22.23.3   | 1.1.0      | HTTP 200   | HTTP 400   | HTTP 200    | VULNERABLE
Node 24.22.0 (Vuln)      | v24.22.0   | 1.1.0      | HTTP 200   | HTTP 400   | HTTP 200    | VULNERABLE
Node 22.23.4 (Patched)   | v22.23.4   | 1.1.1      | HTTP 200   | HTTP 400   | HTTP 400    | PATCHED (SAFE)
Node 24.22.2 (Patched)   | v24.22.2   | 1.2.1      | HTTP 200   | HTTP 400   | HTTP 400    | PATCHED (SAFE)
```

### 6.2. Kiểm chứng Khả năng Phát hiện 3 Tầng (`detection/verify_detections.py`)

Kiểm tra tự động cả 3 lớp phát hiện: (1) Nginx WAF chặn `415` và ghi log, (2) Kiểm tra mã thoát container chống `SIGSEGV (139)`, và (3) Cảnh báo `CRITICAL` từ Falco eBPF:

```bash
sudo LAB_WAF_URL="http://localhost:8085" LAB_DIRECT_URL="http://localhost:3000" \
  python3 detection/verify_detections.py
```

### 6.3. Chạy Đối chứng A/B Trước và Sau khi Khắc phục (`remediation/tests/`)

So sánh trực tiếp giữa container **Chưa vá (`:3000` - `v22.23.3`)** và container **Đã vá (`:3002` - `v22.23.4`)**:

```bash
# 1. Chạy bảng đối chứng trực tiếp A/B (Trước khi vá :3000 vs Sau khi vá :3002)
python3 remediation/tests/compare_labs.py --host localhost --vuln-port 3000 --patched-port 3002 -o evidence/ab_comparison.json

# 2. Chạy kiểm thử nghiệm thu (Re-testing) trên cổng WAF (8085) và App Đã Vá (3002)
python3 remediation/tests/verify_remediation.py --host localhost --waf-port 8085 --app-port 3002
```

---

## 7. Thu thập Bằng chứng Tự động (`evidence.sh`) & Dọn dẹp Lab

### 7.1. Chạy Script Thu thập Bằng chứng Toàn diện (`evidence.sh`)

Chỉ với 1 lệnh duy nhất, `evidence.sh` sẽ tự động thực thi toàn bộ 5 bài kiểm thử, quét ma trận 5 phiên bản Node.js, trích xuất log của các container và đóng gói vào thư mục `./evidence/`:

```bash
# Cú pháp: ./evidence.sh [HOST_IP] [WAF_PORT] [DIRECT_PORT] [EVIDENCE_DIR]
./evidence.sh localhost 8085 3000 evidence
```
Sau khi chạy xong, kiểm tra các tệp kết quả tại:
* `evidence/test_scorecard.json`: Báo cáo JSON tổng hợp kết quả 5 bài test và ma trận 5 phiên bản.
* `evidence/logs/lab-waf.log`, `lab-target-node.log`, `lab-falco-edr.log`, `lab-mock-external.log`.

### 7.2. Dọn dẹp Môi trường Lab sau khi Thực hành

* **Trên Linux / WSL2:**
  ```bash
  ./cleanup-lab.sh
  ```
* **Trên Windows PowerShell:**
  ```powershell
  .\cleanup-lab.ps1
  ```

---

## 8. Xử lý Sự cố Thường gặp (Troubleshooting)

1. **Lỗi vỡ font tiếng Việt (`KHá»žI Äá»˜NG...`) trên Windows PowerShell:**
   * **Nguyên nhân:** Windows PowerShell 5.1 đọc file UTF-8 không có BOM theo bảng mã Windows-1252.
   * **Khắc phục:** Chạy `chcp 65001 > $null` và `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8` trước khi gọi script `.ps1`.
2. **Lỗi `Permission denied` khi chạy script hoặc khi container đọc file trên Linux:**
   * **Nguyên nhân:** SELinux ở chế độ `Enforcing` chặn container đọc thư mục mount, hoặc file bị khóa quyền sở hữu do `sudo`.
   * **Khắc phục:**
     ```bash
     sudo chown -R $USER:$USER .
     sudo chcon -Rt svirt_sandbox_file_t ./detection ./lab ./remediation 2>/dev/null || true
     ```
3. **Container `lab-falco-edr` dừng (`Exited (1)`) trên Windows Docker Desktop (WSL2):**
   * **Nguyên nhân:** Nhân Linux mặc định của Microsoft trên WSL2 không bật `CONFIG_DEBUG_INFO_BTF` cho trình điều khiển `modern_ebpf`.
   * **Khắc phục:** Có thể truyền cờ `--skip-edr`