# SOC Detection & Incident Response Playbook: CVE-2026-111497 (Node2Shell)

## 1. Ma tran Phat hien Da tang (Multi-Layer Detection Matrix)

| Tang Giam sat | Cong cu | Dau hieu Nhan dien (Indicators / Telemetry) | Muc do Uu tien |
| :--- | :--- | :--- | :--- |
| **1. Network / IDS** | **Suricata IDS** (`suricata.rules`) | HTTP POST chua header `Content-Encoding: br` kem chuoi byte `8b 00 00 46 a4` (SID `202611102`) hoac goi do quet `0xff` (SID `202611103`). | High |
| **2. Edge / WAF** | **Nginx WAF** (`nginx_waf.conf`) | Tra ve ma `HTTP 415` khi phat hien `Content-Encoding: br` hoac `HTTP 413` khi kich thuoc body vuot `1MB`. | Medium / Block |
| **3. Container / Host** | **Docker Daemon / Auditd** | Container Node.js khoi dong lai bat thuong voi ma thoat **`Exit Code 139 (SIGSEGV)`** (dau hieu ghi tran bo nho Out-of-Bounds Write). | High |
| **4. Kernel Runtime** | **Falco eBPF** (`falco_rules.yaml`) | Tien trinh cha `node` goi syscall `execve` de khoi tao `/bin/sh`, `/bin/bash` hoac cong cu mang (`curl`, `nc`). | **CRITICAL** |

---

## 2. Quy trinh Xu ly Su co (Incident Response Steps)

1. **Phat hien & Xac minh (Triage):**
   - Kiem tra canh bao tu Falco (`docker logs lab-falco-edr`) va log bao mat cua Nginx (`/var/log/nginx/node2shell_security.log`).
   - Xac minh phien bản Node.js va `libbrotli` dang chay (`node -p "process.versions"`).
2. **Co lap & Thu thap Bang chung (Containment & Forensics):**
   - Khong xoa ngay container bi nghi ngo; tam ngat ket noi mang hoac dung `docker pause <container>` de giu nguyen trang thai bo nho.
   - Trich xuat log he thong va goi tin mang (`.pcap`) phuc vu dieu tra.
3. **Ngan chan Khan cap (Virtual Patching):**
   - Ap dung file `nginx_waf.conf` tai tang Reverse Proxy de chan toan bo header `Content-Encoding: br` va xoa `br` khoi `Accept-Encoding`.
4. **Khac phuc Triet de (Eradication & Recovery):**
   - Rebuild Docker Image voi phien ban Node.js da va (`v22.23.4+`, `v24.22.2+`, `v26.12.1+`) co `libbrotli >= 1.1.1 / 1.2.1`.
   - Chay lai script `verify_detections.py` de xac nhan he thong giam sat hoat dong on dinh.
