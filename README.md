# CVE-2026-111497 ("Node2Shell") — Full-Stack Purple Team & Multi-Version Lab

Kho mã nguồn hợp nhất toàn bộ môi trường mô phỏng, kiểm thử tấn công phân tách theo module (`attacker/`), giám sát đa tầng (`detection/`), khắc phục & đối chứng (`remediation/`) và **5 thư mục phiên bản Node.js cô lập (`lab/`)**.

## Cấu trúc Cây Thư mục Đã Cập nhật (`CVE-2026-111497-main/`)

```text
CVE-2026-111497-main/
├── Makefile                                  # Điều phối trung tâm: make up, make test, make matrix, make compare, make evidence
├── docker-compose.yml                        # Master Compose: Kết nối WAF + 5 Node Versions + Falco eBPF + Dozzle UI
├── start-lab.sh                              # Khởi chạy toàn bộ Lab (Tự động xử lý SELinux trên Fedora)
├── cleanup-lab.sh                            # Dọn dẹp toàn bộ container và mạng ảo
│
├── lab/                                      # [PHÂN HỆ 1] CÁC PHIÊN BẢN NODE.JS TÁCH RIÊNG ĐỘC LẬP
│   ├── docker-compose.yml                    # Chạy riêng cụm 5 phiên bản Node.js + Mock External Server
│   ├── compare_versions_matrix.py            # Script đối chứng đồng loạt cả 5 phiên bản (0 dependencies)
│   ├── node-20.19.5-vuln/                    # (Port 3020) Nhánh 20.x EOL - Chưa vá (libbrotli 1.0.9)
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── .env
│   │   ├── package.json
│   │   └── server.js
│   ├── node-22.23.3-vuln/                    # (Port 3000 & 3022) Nhánh 22.x LTS - Chưa vá (libbrotli 1.1.0)
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── .env
│   │   ├── package.json
│   │   └── server.js
│   ├── node-24.22.0-vuln/                    # (Port 3024) Nhánh 24.x Current - Chưa vá (libbrotli 1.1.0)
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── .env
│   │   ├── package.json
│   │   └── server.js
│   ├── node-22.23.4-patched/                 # (Port 3002 & 3025) Nhánh 22.x LTS - ĐÃ VÁ (libbrotli 1.1.1)
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── .env
│   │   ├── package.json
│   │   └── server.js
│   ├── node-24.22.2-patched/                 # (Port 3026) Nhánh 24.x Current - ĐÃ VÁ (libbrotli 1.2.1)
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── .env
│   │   ├── package.json
│   │   └── server.js
│   └── mock-external/                        # (Port 4000 nội bộ) Giả lập máy chủ bên ngoài test Outbound
│       ├── Dockerfile
│       └── mock-external.js
│
├── attacker/                                 # [PHÂN HỆ 2] BỘ KIỂM THỬ TẤN CÔNG (CHẠY TỪ KALI VM HOẶC HOST)
│   └── scripts/
│       ├── common.py                         # Thư viện HTTP dùng chung (Chỉ dùng thư viện chuẩn Python)
│       ├── test_01_recon_version.py          # Test 01: Kiểm tra phiên bản Binary & C++ libbrotli
│       ├── test_02_differential_probe.py     # Test 02: Kiểm thử vi sai (0x3b vs 0xff)
│       ├── test_03_inbound_waf_and_dos.py    # Test 03: Kiểm thử WAF chặn HTTP 415 & chống sập Stream
│       ├── test_04_outbound_ssrf_client.py   # Test 04: Kiểm thử phơi nhiễm Outbound fetch() Accept-Encoding
│       ├── test_05_edr_rce_telemetry.py      # Test 05: Kích hoạt RCE giả lập & kiểm tra cảnh báo Falco eBPF
│       ├── compare_versions_matrix.py        # Chạy so sánh ma trận 5 phiên bản Node.js từ xa
│       ├── run_all_tests.py                  # Master Test Runner tổng hợp bảng điểm Scorecard
│       ├── run_tests.sh                      # Script chạy nhanh tự động nhận diện WSL2 / Fedora / Kali
│       └── run_lab_tests.sh / .ps1 / .bat    # Menu tương tác CLI đa nền tảng
│
├── detection/                                # [PHÂN HỆ 3] PHÁT HIỆN & GIÁM SÁT ĐA TẦNG (SOC / BLUE TEAM)
│   ├── falco_rules.yaml                      # Luật eBPF bắt syscall execve khi tiến trình `node` gọi `/bin/sh`
│   ├── suricata.rules                        # Luật IDS bắt luồng Brotli Probe (8b 00 00 46 a4) & 0xff
│   ├── auditd.rules                          # Luật Linux Auditd giám sát thực thi shell trên máy chủ
│   ├── nginx_waf.conf                        # Cấu hình Nginx WAF chặn Content-Encoding: br & ghi log an ninh
│   ├── verify_detections.py                  # Script tự động kiểm chứng 3 tầng phát hiện
│   └── PLAYBOOK.md                           # Quy trình phản ứng sự cố 4 bước cho SOC
│
├── remediation/                              # [PHÂN HỆ 4] KHẮC PHỤC, GIA CỐ & NGHIỆM THU (PATCHING & HARDENING)
│   ├── REMEDIATION_SUMMARY.md                # Hướng dẫn khắc phục 4 lớp (Runtime, WAF, Outbound Code, Container)
│   ├── docker-compose-patched.yml            # Cụm Docker Hardened (Non-root, Read-only FS, Cap Drop ALL)
│   ├── configs/
│   │   ├── patched_target.Dockerfile         # Dockerfile nâng cấp Node.js >= 22.23.4 & USER node
│   │   ├── nginx.conf.hardened               # Cấu hình Nginx WAF đã gia cố
│   │   ├── aws_waf_rule.json                 # Mẫu Rule AWS WAF theo khuyến nghị của AWS Security Bulletin
│   │   └── server.js.hardened                # Code Backend đã lọc bỏ `br` chiều ra và giới hạn 1MB giải nén
│   ├── patches/
│   │   └── apply_remediation.sh              # Script tự động triển khai bản vá và chạy nghiệm thu
│   └── tests/
│       ├── verify_remediation.py             # Kiểm thử nghiệm thu 5 tiêu chí sau khi vá
│       └── compare_labs.py                   # Đối chứng trực tiếp A/B (Trước khi vá vs Sau khi vá)
│
├── scripts/
│   └── collect_evidence.sh                   # Tự động thu thập toàn bộ JSON Scorecard & Container Logs
└── evidence/                                 # Thư mục lưu trữ kết quả chấm điểm và log bằng chứng
```
