# TÀI LIỆU KHẮC PHỤC & GIA CỐ HỆ THỐNG (REMEDIATION GUIDE): CVE-2026-111497 ("Node2Shell")

Tài liệu này tổng hợp chiến lược khắc phục đa tầng (Defense-in-Depth) cho lỗ hổng **CVE-2026-111497 (Node2Shell)** dựa trên khuyến nghị từ Node.js Security Advisory, MSRC, AWS, Akamai và Imperva.

---

## 1. Bốn Lớp Khắc phục & Giảm thiểu Rủi ro (4-Layer Defense-in-Depth)

| Lớp Bảo vệ | Hạng mục Thực hiện | File Cấu hình trong `remediation/` | Tính chất |
| :--- | :--- | :--- | :--- |
| **Lớp 1: Runtime Binary (Root Fix)** | Nâng cấp nhân Node.js lên phiên bản tích hợp Google Brotli `1.0.10`, `1.1.1` hoặc `1.2.1+` (`v22.23.4+`, `v24.22.1+` / `v24.22.2+`, `v26.12.1+`). Di chuyển khỏi các nhánh EOL (`18.x`, `20.x`, `23.x`, `25.x`). | `configs/patched_target.Dockerfile` | **Triệt để (Complete Remediation)** |
| **Lớp 2: Edge / WAF (Inbound Mitigation)** | Cấu hình Nginx / AWS WAF từ chối mọi HTTP Request có header `Content-Encoding: br` (trả về `HTTP 415`), giới hạn `client_max_body_size 1m` và lọc bỏ `br` khỏi `Accept-Encoding`. | `configs/nginx.conf.hardened`<br>`configs/aws_waf_rule.json` | **Tạm thời (Virtual Patching)** |
| **Lớp 3: Code & HTTP Client (Outbound & Stream)** | Ghi đè header `Accept-Encoding: gzip, deflate` trên toàn bộ lệnh `fetch()`, `undici`, `axios` chiều ra (vì WAF không bảo vệ được chiều Outbound). Bắt lỗi `.on('error')` và giới hạn kích thước stream giải nén. | `configs/server.js.hardened` | **Gia cố Ứng dụng (Code Hardening)** |
| **Lớp 4: Container & OS Isolation (Blast Radius)** | Chạy tiến trình với quyền `USER node` (Non-root), bật `read_only: true` filesystem, `cap_drop: [ALL]`, `no-new-privileges:true` và giới hạn RAM để cô lập ảnh hưởng dây chuyền. | `docker-compose-patched.yml` | **Cô lập Tác động (Blast Radius Limit)** |

---

## 2. Hướng dẫn Áp dụng Bản vá & Kiểm thử Đối chứng A/B

### Bước 1: Triển khai môi trường Đã Vá & Gia cố (Hardened Environment)
```bash
chmod +x remediation/patches/apply_remediation.sh
./remediation/patches/apply_remediation.sh
```

### Bước 2: Chạy Kiểm thử Nghiệm thu (Verification)
```bash
python3 remediation/tests/verify_remediation.py
```

### Bước 3: Chạy So sánh Đối chứng Trước & Sau khi Vá (A/B Comparison)
```bash
python3 remediation/tests/compare_labs.py -o remediation_comparison_report.json
```
