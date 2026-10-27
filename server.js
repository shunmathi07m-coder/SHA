/**
 * Which One Did I Send? — Lightweight Demo Server
 * Pure Node.js standard library HTTP server (zero npm dependencies required).
 * Serves the project files, extension dashboard, and interactive demo.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8'
};

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url);
  let pathname = decodeURIComponent(parsedUrl.pathname);

  // Default redirect root to demo/index.html
  if (pathname === '/' || pathname === '') {
    res.writeHead(302, { Location: '/demo/index.html' });
    return res.end();
  }

  // Security: Prevent directory traversal
  const safePath = path.normalize(path.join(ROOT_DIR, pathname));
  if (!safePath.startsWith(ROOT_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('403 Forbidden');
  }

  fs.stat(safePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`
        <div style="font-family: sans-serif; padding: 40px; text-align: center;">
          <h2>404 — Not Found</h2>
          <p>File <code>${pathname}</code> was not found.</p>
          <a href="/demo/index.html">Go to Which One Did I Send? Demo</a>
        </div>
      `);
    }

    const ext = path.extname(safePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache'
    });

    const stream = fs.createReadStream(safePath);
    stream.pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🛡️  "Which One Did I Send?" — Localhost Demo Server`);
  console.log(`🚀  Running at: http://localhost:${PORT}/demo/index.html`);
  console.log(`📊  Dashboard at: http://localhost:${PORT}/dashboard/dashboard.html`);
  console.log(`======================================================\n`);
});
