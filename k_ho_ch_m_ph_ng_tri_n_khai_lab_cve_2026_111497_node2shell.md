# Kế hoạch Mô phỏng & Triển khai Cybersec Lab: CVE-2026-111497 ("Node2Shell")

Tài liệu này cung cấp kế hoạch tổng thể và hướng dẫn triển khai nhanh (Turn-key Lab) phục vụ diễn tập **Purple Team (Tấn công & Phòng thủ)** đối với lỗ hổng **CVE-2026-111497 (Node2Shell)** trên môi trường Node.js.

## 1. Tổng quan Lỗ hổng & Cơ chế Kỹ thuật

### 1.1. Thông tin định danh

* **Mã định danh:** CVE-2026-111497 (Biệt danh: **Node2Shell**)

* **Điểm CVSS v4:** **9.2 (Critical)** (Đã đưa vào danh mục CISA KEV)

* **Loại lỗi:** Ghi tràn bộ nhớ ngoài phạm vi (Out-of-Bounds Write - CWE-787) & Không kiểm tra giá trị trả về (Unchecked Return Value - CWE-252)

* **Thành phần bị ảnh hưởng:** Thư viện C/C++ Google Brotli (`1.0.3` đến `1.2.0`) được biên dịch tĩnh bên trong mô-đun `node:zlib` của Node.js.

* **Phiên bản Node.js đã vá:** `v22.23.4+`, `v24.22.2+`, `v26.12.1+` (Các bản EOL như Node 18, 20 không có bản vá).

### 1.2. Cơ chế hoạt động của Brotli và Nguyên nhân gốc rễ

Brotli nén dữ liệu dựa trên sự kết hợp giữa thuật toán cửa sổ trượt **LZ77**, mã hóa **Huffman/Context Modeling** và một **Từ điển tĩnh dựng sẵn (\~122 KB)**.

Khi hoạt động trong Node.js (`node:zlib`), bộ giải nén Brotli chạy dưới dạng một **Máy trạng thái theo luồng (Streaming State Machine)** để xử lý từng gói tin mạng (chunks):

```
[Gói tin mạng (Chunk)] ---> [Bộ đệm nội bộ 8-byte] ---> [Đọc Bit & Block Switch] ---> [Giải nén ra RAM]

```

1. **Quá trình chuyển khối (Block Switch):** Khi dữ liệu thay đổi tính chất, luồng bit chứa lệnh *Block Switch* để đổi bảng mã Huffman. Nếu gói tin mạng chưa truyền tới đủ bit, bộ giải nén lưu tạm các byte đang đọc dở vào một bộ đệm nội bộ 8-byte và trả về trạng thái `NEEDS_MORE_INPUT`.

2. **Điểm kích hoạt lỗi:** Khi gặp một lệnh *Block Switch* bị làm sai lệch có chủ đích (malformed), hàm xử lý lỗi lại trả về trạng thái khiến vòng lặp giải nén hiểu nhầm là *"chưa đủ dữ liệu đầu vào"* thay vì dừng lại và báo lỗi hỏng định dạng (`BROTLI_DECODER_ERROR_FORMAT`).

3. **Hệ quả:** Ở các gói tin tiếp theo, bộ giải nén tiếp tục ghi nối tiếp (append) dữ liệu vào bộ đệm 8-byte mà không kiểm tra giới hạn, dẫn đến **ghi đè lên vùng nhớ liền kề của tiến trình Node.js**, gây sập dịch vụ (`SIGSEGV`) hoặc Thực thi mã từ xa (RCE).

## 2. Mục tiêu của Kịch bản Mô phỏng (Simulation Objectives)

Bài Lab không sử dụng mã khai thác làm tràn bộ nhớ thực tế mà đánh giá **5 khía cạnh phòng thủ cốt lõi**:

| Kịch bản | Mục tiêu Đánh giá | Ý nghĩa Thực tiễn | 
| ----- | ----- | ----- | 
| **1. Rà soát Binary (Recon)** | Điểm mù trong quản lý chuỗi cung ứng (`process.versions.brotli`) | Vì Brotli nằm trong nhân thực thi `node`, lệnh `npm audit` sẽ báo cáo **0 lỗi**. Cần đánh giá khả năng quét tới tầng runtime binary. | 
| **2a. Chặn tại WAF (Inbound)** | Cô lập bề mặt tấn công chiều vào (`Content-Encoding: br`) | Kiểm tra khả năng cắt đứt luồng dữ liệu Brotli ngay tại Reverse Proxy/WAF trước khi gói tin chạm tới `node:zlib`. | 
| **2b. Luồng dữ liệu lỗi (Resilience)** | Độ bền vững của ứng dụng khi giải nén lỗi | Kiểm tra xem Backend có bắt sự kiện `.on('error')` trên luồng giải nén hay để sập toàn bộ Event Loop khi nhận gói tin hỏng. | 
| **3. Phơi nhiễm chiều ra (Outbound)** | Bề mặt tấn công ẩn từ HTTP Client (`fetch` / `undici`) | Mặc định `fetch()` của Node.js tự động gửi `Accept-Encoding: br`. Nếu gọi tới URL/Webhook bên ngoài, máy chủ độc hại có thể trả về gói tin Brotli để tấn công ngược lại. | 
| **4. Cảnh báo RCE & Crash (EDR)** | Khả năng phát hiện hậu khai thác tại tầng Kernel | Kiểm tra xem Falco/EDR có phát hiện ngay lập tức khi tiến trình `node` sinh ra `/bin/sh` hoặc chết đột ngột với mã `139 (SIGSEGV)` hay không. | 

## 3. Kiến trúc & Triển khai Môi trường Lab (Docker Compose)

### 3.1. Sơ đồ Kiến trúc Lab

```
[Trình duyệt / curl] 
       │
       ▼ (Cổng 8080)
┌──────────────────────┐
│  Nginx WAF / Proxy   │ ──► Chặn nếu có Header "Content-Encoding: br" (Trả về HTTP 415)
└──────────┬───────────┘
           │ (Mạng nội bộ cyber-net)
           ▼ (Cổng 3000)
┌──────────────────────┐        Outbound fetch()       ┌────────────────────────┐
│  Target Node.js App  │ ────────────────────────────► │  Mock External Server  │
│  (Backend + Web UI)  │                               │      (Cổng 4000)       │
└──────────┬───────────┘                               └────────────────────────┘
           │
           ▼ (Giám sát Syscalls execve / SIGSEGV)
┌──────────────────────┐
│  Falco eBPF Runtime  │ ──► Báo động CRITICAL nếu `node` gọi `/bin/sh`
└──────────────────────┘

```

### 3.2. Cấu trúc Thư mục

Chạy lệnh sau để tạo cấu trúc thư mục cho Lab:

```
mkdir -p node2shell-lab/{nginx,falco,app} && cd node2shell-lab

```

Cấu trúc file hoàn chỉnh:

```
node2shell-lab/
├── docker-compose.yml
├── nginx/
│   └── default.conf
├── falco/
│   └── node2shell_rules.yaml
└── app/
    ├── server.js
    └── mock-external.js

```

### 3.3. Nội dung các File Cấu hình

#### A. File `docker-compose.yml`

```
services:
  # 1. Tầng WAF / Reverse Proxy
  waf:
    image: nginx:alpine
    container_name: lab-waf
    ports:
      - "8080:80"
    volumes:
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - target-app
    networks:
      - cyber-net

  # 2. Ứng dụng Node.js mục tiêu (Tích hợp Backend API & Web UI Console)
  target-app:
    image: node:22-alpine
    container_name: lab-target-node
    working_dir: /app
    volumes:
      - ./app:/app:ro
    ports:
      - "3000:3000" # Mở cổng trực tiếp để test kịch bản Bypass WAF
    command: node server.js
    networks:
      - cyber-net

  # 3. Máy chủ bên ngoài giả lập (Kiểm tra Outbound SSRF / Webhook)
  external-server:
    image: node:22-alpine
    container_name: lab-external-mock
    working_dir: /app
    volumes:
      - ./app:/app:ro
    command: node mock-external.js
    networks:
      - cyber-net

  # 4. Hệ thống phát hiện xâm nhập Runtime (Falco eBPF)
  falco:
    image: falcosecurity/falco-no-driver:latest
    container_name: lab-falco-edr
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - /proc:/host/proc:ro
      - /etc:/host/etc:ro
      - ./falco/node2shell_rules.yaml:/etc/falco/rules.d/node2shell_rules.yaml:ro
    command: ["/usr/bin/falco", "-o", "engine.kind=modern_ebpf"]
    networks:
      - cyber-net

networks:
  cyber-net:
    driver: bridge

```

#### B. File `nginx/default.conf` (Cấu hình WAF)

```
log_format security_log '$remote_addr - [$time_local] "$request" '
                        'status=$status content_encoding="$http_content_encoding" '
                        'user_agent="$http_user_agent"';

server {
    listen 80;
    access_log /var/log/nginx/access.log security_log;

    location / {
        # Rule tạm thời chặn CVE-2026-111497 chiều vào
        if ($http_content_encoding ~* "\bbr\b") {
            return 415 '{"status": 415, "message": "WAF Blocked: Brotli encoding is disabled due to CVE-2026-111497"}\n';
        }

        proxy_pass http://target-app:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

```

#### C. File `falco/node2shell_rules.yaml` (Luật phát hiện RCE)

```
- rule: Node2Shell Post-Exploitation Detected
  desc: Phat hien tien trinh Node.js sinh ra Shell hoac chay lenh he thong (Dau hieu RCE CVE-2026-111497)
  condition: >
    evt.type = execve and
    evt.dir = < and
    proc.pname in (node, nodejs) and
    proc.name in (sh, bash, ash, dash, zsh, id, whoami, uname, curl, wget, nc, netcat)
  output: >
    [CRITICAL ALERT - NODE2SHELL] Tiến trình Node.js vừa gọi lệnh hệ thống!
    (Container=%container.name Parent=%proc.pname Command="%proc.cmdline" User=%user.name)
  priority: CRITICAL
  tags: [process, rce, cve-2026-111497]

```

#### D. File `app/server.js` (Backend Mục tiêu + Giao diện Điều khiển)

```
import http from 'node:http';
import zlib from 'node:zlib';
import { exec } from 'node:child_process';

const server = http.createServer((req, res) => {
  // Giao diện Web UI Dashboard phục vụ Demo / Purple Team
  if (req.url === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Node2Shell (CVE-2026-111497) Purple Team Lab</title>
        <style>
          body { font-family: system-ui, sans-serif; max-width: 850px; margin: 30px auto; background: #0f172a; color: #f8fafc; padding: 20px; }
          .card { background: #1e293b; padding: 15px 20px; margin-bottom: 15px; border-radius: 8px; border: 1px solid #334155; }
          h3 { margin-top: 0; color: #e2e8f0; }
          button { background: #3b82f6; color: white; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; margin-right: 10px; margin-top: 5px; }
          button.danger { background: #ef4444; }
          button.safe { background: #10b981; }
          pre { background: #020617; padding: 14px; border-radius: 6px; overflow-x: auto; color: #38bdf8; border: 1px solid #1e293b; min-height: 80px; }
        </style>
      </head>
      <body>
        <h2>🛡️ Node2Shell (CVE-2026-111497) Simulation Console</h2>
        
        <div class="card">
          <h3>1. Kiểm tra Phiên bản Binary (Recon)</h3>
          <button onclick="runTest('/api/info')">Kiểm tra Node & Brotli Version</button>
        </div>

        <div class="card">
          <h3>2. Kiểm thử Chiều vào (Inbound Brotli)</h3>
          <button class="danger" onclick="sendBrotli()">Gửi gói tin Brotli (Test WAF / Decompressor)</button>
        </div>

        <div class="card">
          <h3>3. Kiểm thử Chiều ra (Outbound Fetch Exposure)</h3>
          <button class="danger" onclick="runTest('/api/webhook-test')">Fetch Mặc định (Nguy hiểm)</button>
          <button class="safe" onclick="runTest('/api/webhook-test', {'x-safe-outbound': 'true'})">Fetch Đã cấu hình Chặn Br (An toàn)</button>
        </div>

        <div class="card">
          <h3>4. Kiểm thử Cảnh báo EDR / Falco (Post-Exploitation)</h3>
          <button class="danger" onclick="runTest('/sim/rce-trigger', {}, 'POST')">Kích hoạt Giả lập RCE (Node gọi /bin/sh)</button>
        </div>

        <h3>Kết quả phản hồi từ Server:</h3>
        <pre id="output">Chưa có thao tác nào...</pre>

        <script>
          async function runTest(url, headers = {}, method = 'GET') {
            document.getElementById('output').textContent = 'Đang gửi request...';
            const res = await fetch(url, { method, headers });
            const text = await res.text();
            document.getElementById('output').textContent = 'HTTP Status: ' + res.status + '\\n\\n' + text;
          }

          async function sendBrotli() {
            document.getElementById('output').textContent = 'Đang gửi gói tin có Content-Encoding: br...';
            const fakeBrotliBytes = new Uint8Array([0x1b, 0x00, 0x00, 0xff, 0xff]);
            const res = await fetch('/api/upload', {
              method: 'POST',
              headers: { 'Content-Encoding': 'br' },
              body: fakeBrotliBytes
            });
            const text = await res.text();
            document.getElementById('output').textContent = 'HTTP Status: ' + res.status + '\\n\\n' + text;
          }
        </script>
      </body>
      </html>
    `);
    return;
  }

  // 1. Endpoint kiểm tra phiên bản Runtime & Brotli nội tại
  if (req.url === '/api/info') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      nodeVersion: process.version,
      brotliVersion: process.versions.brotli,
      zlibVersion: process.versions.zlib
    }, null, 2) + '\n');
    return;
  }

  // 2. Endpoint nhận dữ liệu nén Brotli (Inbound Vector)
  if (req.url === '/api/upload' && req.method === 'POST') {
    if (req.headers['content-encoding'] === 'br') {
      const brotli = zlib.createBrotliDecompress();
      let output = '';

      req.pipe(brotli);
      brotli.on('data', chunk => { output += chunk.toString(); });
      brotli.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'OK', decompressedData: output }) + '\n');
      });
      brotli.on('error', err => {
        console.error(`[ERROR_LOG] Malformed Brotli stream detected: ${err.code} - ${err.message}`);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Decompression failed', code: err.code }) + '\n');
      });
      return;
    }
    res.writeHead(200);
    res.end('Uncompressed upload received\n');
    return;
  }

  // 3. Endpoint gọi ra máy chủ bên ngoài (Outbound Client Vector)
  if (req.url === '/api/webhook-test') {
    const safeMode = req.headers['x-safe-outbound'] === 'true';
    const customHeaders = safeMode ? { 'Accept-Encoding': 'gzip, deflate' } : {};

    fetch('http://external-server:4000/check', { headers: customHeaders })
      .then(r => r.json())
      .then(data => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data, null, 2) + '\n');
      })
      .catch(err => {
        res.writeHead(500);
        res.end(err.message);
      });
    return;
  }

  // 4. Endpoint giả lập hành vi RCE (Chỉ phục vụ test EDR/Falco)
  if (req.url === '/sim/rce-trigger' && req.method === 'POST') {
    exec('/bin/sh -c "id && uname -r"', (error, stdout) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`Simulated RCE Executed:\n${stdout}`);
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found\n');
});

server.listen(3000, () => {
  console.log(`[TARGET] Server running on port 3000 | Node: ${process.version} | Brotli: ${process.versions.brotli}`);
});

```

#### E. File `app/mock-external.js` (Máy chủ Giả lập Bên ngoài)

```
import http from 'node:http';

http.createServer((req, res) => {
  const acceptEncoding = req.headers['accept-encoding'] || '';
  const isExposed = /\bbr\b/.test(acceptEncoding);

  console.log(`[EXTERNAL_MOCK] Incoming request with Accept-Encoding: "${acceptEncoding}"`);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    clientSentAcceptEncoding: acceptEncoding,
    exposedToMaliciousBrotliResponse: isExposed,
    recommendation: isExposed
      ? 'VULNERABLE: Override Accept-Encoding to "gzip, deflate"'
      : 'SAFE: Brotli is excluded from outbound client headers'
  }));
}).listen(4000, () => console.log('[EXTERNAL_MOCK] Listening on port 4000'));

```

## 4. Quy trình Vận hành & Thực hành Kiểm thử

### Bước 1: Khởi động Lab và Giám sát Log (Blue Team)

Khởi chạy các container:

```
docker compose up -d

```

Mở một cửa sổ Terminal riêng để theo dõi trực tiếp cảnh báo từ WAF, Backend và Falco EDR:

```
docker compose logs -f waf target-app falco

```

*(Bạn cũng có thể mở trình duyệt truy cập `http://localhost:8080` để chạy qua giao diện Web UI hoặc truy cập `http://localhost:3000` để test kịch bản bỏ qua WAF).*

### Bước 2: Thực thi 5 Kịch bản Kiểm thử (Red / Purple Team)

#### Kịch bản 1: Trinh sát Phiên bản (Reconnaissance)

```
curl http://localhost:8080/api/info

```

* **Đánh giá:** Kiểm tra trường `brotliVersion`. Nếu phiên bản nằm trong khoảng `1.0.3` đến `1.2.0` (chưa lên `1.1.1` hoặc `1.2.1`), runtime đang tồn tại lỗ hổng.

#### Kịch bản 2: Tấn công Chiều vào qua WAF và Bypass WAF (Inbound Vector)

* **Test 2a - Đi qua WAF (Cổng 8080):**

  ```
  printf "\x1b\x00\x00\xff\xff" | curl -i -X POST http://localhost:8080/api/upload \
    -H "Content-Encoding: br" --data-binary @-
  
  ```

  *Kết quả mong đợi:* WAF chặn ngay lập tức với mã `HTTP/1.1 415 Unsupported Media Type`.

* **Test 2b - Đi thẳng vào Backend (Cổng 3000 - Bypass WAF):**

  ```
  printf "\x1b\x00\x00\xff\xff" | curl -i -X POST http://localhost:3000/api/upload \
    -H "Content-Encoding: br" --data-binary @-
  
  ```

  *Kết quả mong đợi:* Gói tin đi vào `zlib.createBrotliDecompress()`, kích hoạt nhánh `.on('error')`, trả về HTTP `400` và ghi log `[ERROR_LOG] Malformed Brotli stream detected` mà không làm sập tiến trình Node.js.

#### Kịch bản 3: Kiểm tra Phơi nhiễm Chiều ra (Outbound Client Vector)

* **Chế độ mặc định:**

  ```
  curl http://localhost:8080/api/webhook-test
  
  ```

  *Kết quả:* Trả về `"exposedToMaliciousBrotliResponse": true`.

* **Chế độ đã giảm thiểu (Ghi đè `Accept-Encoding`):**

  ```
  curl -H "x-safe-outbound: true" http://localhost:8080/api/webhook-test
  
  ```

  *Kết quả:* Trả về `"exposedToMaliciousBrotliResponse": false`.

#### Kịch bản 4: Phát hiện Hậu khai thác RCE (Falco eBPF)

```
curl -X POST http://localhost:8080/sim/rce-trigger

```

* **Kết quả mong đợi:** Màn hình log của Falco lập tức xuất hiện cảnh báo:
  `[CRITICAL ALERT - NODE2SHELL] Tiến trình Node.js vừa gọi lệnh hệ thống! (Container=lab-target-node Parent=node Command="sh -c id && uname -r" ...)`

#### Kịch bản 5: Mô phỏng Lỗi Phân đoạn Bộ nhớ (Memory Corruption / SIGSEGV)

```
docker kill --signal=SIGSEGV lab-target-node
docker inspect lab-target-node --format='ExitCode: {{.State.ExitCode}}'

```

* **Kết quả mong đợi:** Container dừng với `ExitCode: 139`. Khởi động lại container bằng lệnh `docker start lab-target-node`.

## 5. Bảng Nghiệm thu Diễn tập (Purple Team Scorecard)

| STT | Hạng mục Kiểm tra | Chốt chặn / Công cụ | Kết quả Mong đợi | Đạt / Chưa đạt | 
| ----- | ----- | ----- | ----- | ----- | 
| **1** | Rà soát Binary (`process.versions.brotli`) | Container Scanner / Script kiểm tra | Phát hiện chính xác các image chứa Node.js chưa vá | \[ \] | 
| **2** | Chặn `Content-Encoding: br` chiều vào | Nginx WAF / Cloud WAF | Trả về HTTP `415`, ngăn gói tin chạm tới `node:zlib` | \[ \] | 
| **3** | Bắt lỗi luồng giải nén hỏng | Sự kiện `brotli.on('error')` | Ghi log lỗi giải nén, tiến trình Node.js không bị crash | \[ \] | 
| **4** | Loại bỏ `br` khỏi HTTP Client chiều ra | Cấu hình Header `fetch` / `axios` | Header `Accept-Encoding` chỉ gửi `gzip, deflate` | \[ \] | 
| **5** | Phát hiện `node` gọi Shell (`/bin/sh`) | Falco / EDR | Báo động mức **CRITICAL** ngay khi lệnh thực thi | \[ \] | 
| **6** | Phát hiện Crash bộ nhớ (`SIGSEGV`) | Docker / K8s Event Monitoring | Cảnh báo khi container thoát với mã lỗi `139` | \[ \] | 

## 6. Dọn dẹp Môi trường Lab

Sau khi hoàn thành buổi diễn tập, chạy lệnh sau để gỡ bỏ toàn bộ container và mạng ảo:

```
docker compose down -v

```