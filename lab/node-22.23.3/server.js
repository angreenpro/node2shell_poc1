const http = require('http');
const zlib = require('zlib');
const { exec } = require('child_process');

const PORT = process.env.PORT || 3000;
const PROFILE_NAME = process.env.PROFILE_NAME || 'node-22.23.3';
const SIM_NODE_VER = process.env.SIM_NODE_VER || 'v22.23.3';
const SIM_BROTLI_VER = process.env.SIM_BROTLI_VER || '1.1.0';
const MOCK_EXT_URL = process.env.MOCK_EXT_URL || 'http://mock-external:4000/check';

function isBrotliPatched(verStr) {
  const parts = String(verStr).split('.').map(x => parseInt(x, 10) || 0);
  const [maj, min, pat] = [parts[0] || 0, parts[1] || 0, parts[2] || 0];
  if (maj > 1) return true;
  if (maj === 1 && min === 2 && pat >= 1) return true;
  if (maj === 1 && min === 1 && pat >= 1) return true;
  if (maj === 1 && min === 0 && pat >= 10) return true;
  return false;
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');

  // 1. Endpoint kiem tra phien ban Runtime & Brotli
  if (req.url === '/api/info' && req.method === 'GET') {
    const patched = isBrotliPatched(SIM_BROTLI_VER);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      profile: PROFILE_NAME,
      nodeVersion: SIM_NODE_VER,
      brotliVersion: SIM_BROTLI_VER,
      zlibVersion: process.versions.zlib,
      status: patched ? 'PATCHED' : 'VULNERABLE'
    }, null, 2));
  }

  // 2. Endpoint kiem thu giai nen Brotli Chieu vao
  if (req.url === '/api/upload' && req.method === 'POST') {
    const encoding = (req.headers['content-encoding'] || '').toLowerCase();
    const patched = isBrotliPatched(SIM_BROTLI_VER);

    if (!encoding.includes('br')) {
      if (encoding && encoding !== 'identity') {
        res.writeHead(415, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unsupported Content-Encoding', encoding }));
      }
      let raw = [];
      req.on('data', chunk => raw.push(chunk));
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ profile: PROFILE_NAME, mode: 'plain', bytes: Buffer.concat(raw).length }));
      });
      return;
    }

    let rawChunks = [];
    req.on('data', c => rawChunks.push(c));
    req.on('end', () => {
      const fullBuf = Buffer.concat(rawChunks);
      if (fullBuf.length >= 5 && fullBuf.subarray(0, 5).equals(Buffer.from('8b000046a4', 'hex'))) {
        const code = patched ? 400 : 200;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ profile: PROFILE_NAME, probeAccepted: !patched }));
      }

      zlib.brotliDecompress(fullBuf, (err, decompressed) => {
        if (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Decompression failed safely', code: err.code || 'Z_DATA_ERROR' }));
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Decompressed successfully', outputLength: decompressed.length }));
      });
    });
    return;
  }

  // 3. Endpoint kiem tra cau hinh Header Chieu ra (Outbound HTTP Client)
  if (req.url === '/api/webhook-test' && req.method === 'GET') {
    const safeMode = req.headers['x-safe-outbound'] === 'true';
    try {
      const customHeaders = safeMode ? { 'Accept-Encoding': 'gzip, deflate' } : {};
      const response = await fetch(MOCK_EXT_URL, { headers: customHeaders });
      const data = await response.json();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(data, null, 2));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        clientSentAcceptEncoding: safeMode ? 'gzip, deflate' : 'br, gzip, deflate',
        exposedToMaliciousBrotliResponse: !safeMode
      }));
    }
  }

  // 4. Endpoint kich hoat gia lap RCE Telemetry (Test 05)
  if (req.url === '/sim/rce-trigger' && req.method === 'POST') {
    exec('/bin/sh -c "id && uname -r"', (err, stdout, stderr) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(`[Simulated RCE Executed]\n` + (stdout || stderr));
    });
    return;
  }

  res.writeHead(404);
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`[${PROFILE_NAME}] Listening on port ${PORT}`);
});
