const https = require('https');
const http = require('http');
const crypto = require('crypto');

const PROXY_API_KEY = process.env.PROXY_API_KEY;
const PORT = process.env.PORT || 3000;
const MAX_BODY_SIZE = 10 * 1024 * 1024;
const ALLOWED_DOMAINS = ['auth.sicoob.com.br', 'api.sicoob.com.br'];

if (!PROXY_API_KEY) {
  console.error('PROXY_API_KEY não definida!');
}

function makeMtlsRequest(url, method, headers, body, pfx, passphrase) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const options = {
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      method: method.toUpperCase(),
      headers: { ...headers, Connection: 'close' },
      pfx,
      passphrase,
      rejectUnauthorized: true,
      servername: u.hostname,
    };
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        resolve({
          status: res.statusCode,
          headers: res.headers,
          bodyBase64: buf.toString('base64'),
          bodyText: buf.toString('utf8'),
        });
      });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => req.destroy(new Error('Timeout')));
    if (body) req.write(body);
    req.end();
  });
}

function validateApiKey(providedKey) {
  if (!providedKey || !PROXY_API_KEY) return false;
  const a = Buffer.from(providedKey);
  const b = Buffer.from(PROXY_API_KEY);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
  }
  if (req.method !== 'POST' || req.url !== '/sicoob') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Not found' }));
  }
  let body = '';
  let bodySize = 0;
  let tooLarge = false;
  for await (const chunk of req) {
    bodySize += chunk.length;
    if (bodySize > MAX_BODY_SIZE) { tooLarge = true; break; }
    body += chunk;
  }
  if (tooLarge) {
    res.writeHead(413, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Body too large' }));
  }
  let payload;
  try { payload = JSON.parse(body); }
  catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Invalid JSON' }));
  }
  if (!validateApiKey(payload.api_key)) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }
  const { pfx_base64, password, method, url, headers: reqHeaders, body: reqBody } = payload;
  if (!pfx_base64 || !password || !method || !url) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Missing required fields' }));
  }
  let parsedUrl;
  try { parsedUrl = new URL(url); }
  catch {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Invalid URL' }));
  }
  if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'Domain not allowed' }));
  }
  const pfx = Buffer.from(pfx_base64, 'base64');
  try {
    const result = await makeMtlsRequest(url, method, reqHeaders || {}, reqBody, pfx, password);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
  } catch (err) {
    console.error('mTLS error:', err.message);
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, () => {
  console.log(`Proxy Sicoob rodando na porta ${PORT}`);
});
