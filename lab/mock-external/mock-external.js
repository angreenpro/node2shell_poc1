const http = require('http');

const server = http.createServer((req, res) => {
  const acceptEncoding = req.headers['accept-encoding'] || 'none';
  const isExposedToBrotli = acceptEncoding.includes('br');

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    clientSentAcceptEncoding: acceptEncoding,
    exposedToMaliciousBrotliResponse: isExposedToBrotli,
    recommendation: isExposedToBrotli
      ? 'VULNERABLE OUTBOUND: Client accepts br stream from external server'
      : 'SAFE OUTBOUND: br removed from Accept-Encoding'
  }));
});

server.listen(4000, () => console.log('Mock External Server listening on 4000'));
