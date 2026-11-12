/**
 * Clean VLESS over WebSocket Server for Container Environments
 * Compatible with v2rayNG, V2Box, Streisand, Sing-box, Nekoray, Shadowrocket, Clash-Meta.
 * Designed for Docker, Pterodactyl, BungeeHost, Bot-Hosting, Render, and VPS nodes.
 */

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import { WebSocketServer, WebSocket } from 'ws';

// -------------------------------------------------------------
// 1. Configuration & UUIDs
// -------------------------------------------------------------
const DEFAULT_UUID = '4ed3658d-7f0b-5e27-f826-f75d33f18f7a';
const RAW_UUIDS = (process.env.UUID || process.env.UUIDS || DEFAULT_UUID).trim();

function parseUuid(raw) {
  const clean = raw.replace(/-/g, '').toLowerCase().trim();
  if (!/^[0-9a-f]{32}$/.test(clean)) return null;
  const formatted = `${clean.slice(0, 8)}-${clean.slice(8, 12)}-${clean.slice(12, 16)}-${clean.slice(16, 20)}-${clean.slice(20, 32)}`;
  return { clean, formatted };
}

const VALID_UUIDS = new Set();
const FORMATTED_UUIDS = [];

for (const entry of RAW_UUIDS.split(',')) {
  const p = parseUuid(entry);
  if (p) {
    VALID_UUIDS.add(p.clean);
    FORMATTED_UUIDS.push(p.formatted);
  }
}

if (VALID_UUIDS.size === 0) {
  const def = parseUuid(DEFAULT_UUID);
  VALID_UUIDS.add(def.clean);
  FORMATTED_UUIDS.push(def.formatted);
}

const PRIMARY_UUID = FORMATTED_UUIDS[0];
const PORT = parseInt(process.env.PORT || process.env.SERVER_PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const WSS_PATH = (process.env.WSS_PATH || process.env.VLESS_PATH || '/').trim();
const NODE_NAME = process.env.NODE_NAME || process.env.NODE_ALIAS || 'VLESS-Node';

// TLS auto-detection
const CERT_FILE = process.env.CERT_FILE || path.resolve('cert.pem');
const KEY_FILE = process.env.KEY_FILE || path.resolve('key.pem');
const HAS_TLS = fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE);

// Metrics
let activeConnections = 0;
let totalConnections = 0;
let bytesReceived = 0;
let bytesSent = 0;
const startedAt = Date.now();

// -------------------------------------------------------------
// 2. VLESS Protocol Parser (RFC Spec Compliant)
// -------------------------------------------------------------
function parseVlessHeader(buffer) {
  if (buffer.length < 24) {
    return { error: 'Header too short' };
  }

  const version = buffer[0];
  if (version !== 0) {
    return { error: `Unsupported VLESS version (${version})` };
  }

  // 16 bytes binary UUID
  const clientUuidHex = buffer.subarray(1, 17).toString('hex').toLowerCase();
  if (!VALID_UUIDS.has(clientUuidHex)) {
    return { error: 'Unauthorized UUID' };
  }

  // Addons section
  const addonsLen = buffer[17];
  let cursor = 18 + addonsLen;
  if (buffer.length < cursor + 4) {
    return { error: 'Malformed command section' };
  }

  const command = buffer[cursor]; // 1 = TCP, 2 = UDP, 3 = Mux
  const targetPort = buffer.readUInt16BE(cursor + 1);
  const addressType = buffer[cursor + 3];
  cursor += 4;

  let targetHost = '';
  if (addressType === 1) { // IPv4 (4 bytes)
    if (buffer.length < cursor + 4) return { error: 'Malformed IPv4 address' };
    targetHost = `${buffer[cursor]}.${buffer[cursor + 1]}.${buffer[cursor + 2]}.${buffer[cursor + 3]}`;
    cursor += 4;
  } else if (addressType === 2) { // Domain name (1-byte len + ASCII string)
    const domainLen = buffer[cursor];
    cursor += 1;
    if (buffer.length < cursor + domainLen) return { error: 'Malformed domain name' };
    targetHost = buffer.subarray(cursor, cursor + domainLen).toString('utf8');
    cursor += domainLen;
  } else if (addressType === 3) { // IPv6 (16 bytes)
    if (buffer.length < cursor + 16) return { error: 'Malformed IPv6 address' };
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(buffer.readUInt16BE(cursor + i).toString(16));
    }
    targetHost = parts.join(':');
    cursor += 16;
  } else {
    return { error: `Unsupported address type: ${addressType}` };
  }

  const initialPayload = buffer.subarray(cursor);

  return {
    command,
    targetPort,
    targetHost,
    initialPayload
  };
}

// -------------------------------------------------------------
// 3. TCP Streaming Engine
// -------------------------------------------------------------
function handleTcp(ws, targetHost, targetPort, initialPayload) {
  let isClosed = false;
  let targetSocket = null;
  activeConnections++;
  totalConnections++;

  const cleanup = () => {
    if (isClosed) return;
    isClosed = true;
    activeConnections = Math.max(0, activeConnections - 1);
    if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close();
    }
  };

  ws.on('close', cleanup);
  ws.on('error', cleanup);

  targetSocket = net.connect({ host: targetHost, port: targetPort }, () => {
    if (isClosed) return;

    // Send VLESS response header (version 0, addons length 0)
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(Buffer.from([0x00, 0x00]));
    }

    // Write initial payload (e.g. TLS Client Hello or HTTP GET)
    if (initialPayload && initialPayload.length > 0) {
      targetSocket.write(initialPayload);
      bytesSent += initialPayload.length;
    }

    // 1. WebSocket -> Target TCP (Upload) with backpressure
    ws.on('message', (chunk) => {
      if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
      bytesSent += chunk.length;
      const canWrite = targetSocket.write(chunk);
      if (!canWrite && ws._socket && ws._socket.pause) {
        ws._socket.pause();
      }
    });

    targetSocket.on('drain', () => {
      if (ws._socket && ws._socket.resume) {
        ws._socket.resume();
      }
    });

    // 2. Target TCP -> WebSocket (Download) with backpressure
    targetSocket.on('data', (chunk) => {
      bytesReceived += chunk.length;
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(chunk);
        if (ws.bufferedAmount > 64 * 1024) {
          targetSocket.pause();
        }
      }
    });
  });

  const drainCheck = setInterval(() => {
    if (isClosed) {
      clearInterval(drainCheck);
      return;
    }
    if (targetSocket && targetSocket.isPaused && targetSocket.isPaused() && ws.bufferedAmount < 16 * 1024) {
      targetSocket.resume();
    }
  }, 25);

  targetSocket.on('error', cleanup);
  targetSocket.on('close', cleanup);
}

// -------------------------------------------------------------
// 4. UDP Streaming Engine (DNS & UDP Apps)
// -------------------------------------------------------------
function handleUdp(ws, targetHost, targetPort, initialPayload) {
  let isClosed = false;
  let udpSocket = null;
  activeConnections++;
  totalConnections++;

  const cleanup = () => {
    if (isClosed) return;
    isClosed = true;
    activeConnections = Math.max(0, activeConnections - 1);
    if (udpSocket) {
      try { udpSocket.close(); } catch {}
    }
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close();
    }
  };

  ws.on('close', cleanup);
  ws.on('error', cleanup);

  try {
    udpSocket = dgram.createSocket('udp4');
  } catch {
    cleanup();
    return;
  }

  // Send VLESS response header (version 0, addons length 0)
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(Buffer.from([0x00, 0x00]));
  }

  udpSocket.on('message', (msg) => {
    bytesReceived += msg.length;
    if (ws.readyState === WebSocket.OPEN) {
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(msg.length, 0);
      ws.send(Buffer.concat([lenBuf, msg]));
    }
  });

  udpSocket.on('error', cleanup);

  const forwardUdp = (chunk) => {
    let offset = 0;
    while (offset + 2 < chunk.length) {
      const pLen = chunk.readUInt16BE(offset);
      offset += 2;
      if (offset + pLen <= chunk.length) {
        const packet = chunk.subarray(offset, offset + pLen);
        offset += pLen;
        bytesSent += packet.length;

        // For DNS (port 53), support DoH fallback in case container host blocks UDP 53
        if (targetPort === 53) {
          udpSocket.send(packet, targetPort, targetHost, (err) => {
            if (err) {
              resolveDnsDoH(packet).then((resp) => {
                if (resp && ws.readyState === WebSocket.OPEN) {
                  const lenBuf = Buffer.alloc(2);
                  lenBuf.writeUInt16BE(resp.length, 0);
                  ws.send(Buffer.concat([lenBuf, resp]));
                }
              }).catch(() => {});
            }
          });
        } else {
          udpSocket.send(packet, targetPort, targetHost, () => {});
        }
      } else {
        break;
      }
    }
  };

  if (initialPayload && initialPayload.length > 2) {
    forwardUdp(initialPayload);
  }

  ws.on('message', (chunk) => {
    if (!Buffer.isBuffer(chunk)) chunk = Buffer.from(chunk);
    forwardUdp(chunk);
  });
}

// Fallback DoH resolver for hosters that block outbound port 53
async function resolveDnsDoH(dnsQuery) {
  try {
    let res = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
      body: dnsQuery,
      signal: AbortSignal.timeout(2500)
    });
    if (!res.ok) {
      res = await fetch('https://dns.google/dns-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
        body: dnsQuery,
        signal: AbortSignal.timeout(2500)
      });
    }
    if (res.ok) {
      return Buffer.from(await res.arrayBuffer());
    }
  } catch {}
  return null;
}

// -------------------------------------------------------------
// 5. HTTP Dashboard & Subscription Generator
// -------------------------------------------------------------
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / (3600 * 24));
  const h = Math.floor((seconds % (3600 * 24)) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(' ');
}

function buildVlessUrl(reqHost, isTls) {
  let host = reqHost;
  let port = PORT;

  if (reqHost.includes(':')) {
    const parts = reqHost.split(':');
    host = parts[0];
    port = parseInt(parts[1], 10);
  } else {
    port = isTls ? 443 : 80;
  }

  const security = isTls ? 'tls' : 'none';
  const cleanPath = encodeURIComponent(WSS_PATH.startsWith('/') ? WSS_PATH : `/${WSS_PATH}`);
  return `vless://${PRIMARY_UUID}@${host}:${port}?encryption=none&security=${security}&type=ws&path=${cleanPath}#${encodeURIComponent(NODE_NAME)}`;
}

function handleHttpRequest(req, res) {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = reqUrl.pathname;
  const reqHost = req.headers.host || `localhost:${PORT}`;
  const isTls = HAS_TLS || req.headers['x-forwarded-proto'] === 'https';
  const vlessUrl = buildVlessUrl(reqHost, isTls);

  // Health / Ping endpoint
  if (pathname === '/health' || pathname === '/ping' || pathname === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      status: 'online',
      node: NODE_NAME,
      uptime: Math.floor((Date.now() - startedAt) / 1000),
      activeConnections,
      totalConnections,
      tls: isTls,
      port: PORT
    }));
  }

  // Raw subscription endpoint
  if (pathname === '/sub' || pathname === '/subscription') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(Buffer.from(vlessUrl).toString('base64'));
  }

  // Raw link endpoint
  if (pathname === '/link') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(vlessUrl);
  }

  // Web Dashboard
  const uptimeStr = formatUptime((Date.now() - startedAt) / 1000);
  const rxStr = formatBytes(bytesReceived);
  const txStr = formatBytes(bytesSent);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${NODE_NAME} — VLESS Node</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --primary: #38bdf8;
      --primary-hover: #0ea5e9;
      --green: #22c55e;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      min-height: 100vh;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .container {
      width: 100%;
      max-width: 680px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.4);
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.5rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .header h1 {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--text);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(34, 197, 94, 0.15);
      color: var(--green);
      font-size: 0.85rem;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 9999px;
      border: 1px solid rgba(34, 197, 94, 0.3);
    }
    .dot {
      width: 8px;
      height: 8px;
      background: var(--green);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--green);
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .stat-card {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.85rem;
      text-align: center;
    }
    .stat-label {
      font-size: 0.75rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }
    .stat-val {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--primary);
    }
    .section-title {
      font-size: 0.95rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
      color: var(--text);
    }
    .link-box {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.85rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.8rem;
      color: #bae6fd;
      word-break: break-all;
      margin-bottom: 1rem;
      user-select: all;
    }
    .btn-group {
      display: flex;
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    button, a.btn {
      flex: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: var(--primary);
      color: #0f172a;
      font-weight: 600;
      font-size: 0.9rem;
      padding: 10px 16px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.15s ease;
    }
    button:hover, a.btn:hover {
      background: var(--primary-hover);
    }
    a.btn-secondary {
      background: transparent;
      color: var(--text);
      border: 1px solid var(--border);
    }
    a.btn-secondary:hover {
      background: rgba(255, 255, 255, 0.05);
    }
    .instructions {
      background: rgba(15, 23, 42, 0.4);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
      font-size: 0.85rem;
      color: var(--muted);
      line-height: 1.6;
    }
    .instructions ol {
      margin-left: 1.2rem;
      margin-top: 0.5rem;
    }
    .instructions strong {
      color: var(--text);
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>${NODE_NAME}</h1>
        <div style="font-size: 0.8rem; color: var(--muted); margin-top: 2px;">VLESS over WebSocket Node</div>
      </div>
      <div class="badge"><span class="dot"></span> Online</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Uptime</div>
        <div class="stat-val">${uptimeStr}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Active</div>
        <div class="stat-val">${activeConnections}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Sockets</div>
        <div class="stat-val">${totalConnections}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Traffic</div>
        <div class="stat-val">${txStr} ↑ / ${rxStr} ↓</div>
      </div>
    </div>

    <div class="section-title">VLESS Connection Link</div>
    <div class="link-box" id="vlessLink">${vlessUrl}</div>

    <div class="btn-group">
      <button id="copyBtn" onclick="copyLink()">📋 Copy VLESS Link</button>
      <a class="btn btn-secondary" href="/sub" target="_blank">📥 Subscription Link</a>
    </div>

    <div class="instructions">
      <strong>How to Connect:</strong>
      <ol>
        <li>Click <strong>Copy VLESS Link</strong> above.</li>
        <li>Open your client: <strong>v2rayNG</strong> (Android), <strong>V2Box / Streisand</strong> (iOS), <strong>Sing-box / Nekoray</strong> (PC).</li>
        <li>Select <strong>"+" → Import config from clipboard</strong>.</li>
        <li>Connect and enjoy uncensored internet!</li>
      </ol>
    </div>
  </div>

  <script>
    function copyLink() {
      const text = document.getElementById('vlessLink').innerText;
      navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copyBtn');
        const orig = btn.innerText;
        btn.innerText = '✅ Copied!';
        setTimeout(() => { btn.innerText = orig; }, 2000);
      });
    }
  </script>
</body>
</html>`;

  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

// -------------------------------------------------------------
// 6. Server Initialization
// -------------------------------------------------------------
let server;

if (HAS_TLS && process.env.FORCE_HTTP !== 'true') {
  console.log('[TLS] Loading SSL certificate from cert.pem and key.pem...');
  server = https.createServer({
    cert: fs.readFileSync(CERT_FILE),
    key: fs.readFileSync(KEY_FILE),
    minVersion: 'TLSv1.2'
  }, handleHttpRequest);
  console.log('[TLS] HTTPS and WSS (Encrypted) enabled!');
} else {
  server = http.createServer(handleHttpRequest);
  console.log('[HTTP] Running in standard HTTP / WS mode.');
}

server.on('error', (err) => {
  console.error('[SERVER] Fatal server error:', err.message);
});

// WebSocket Server attached to HTTP(S) server
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  // Wait for initial binary VLESS request frame
  ws.once('message', (initialChunk) => {
    if (!Buffer.isBuffer(initialChunk)) initialChunk = Buffer.from(initialChunk);

    const parsed = parseVlessHeader(initialChunk);
    if (parsed.error) {
      console.warn(`[VLESS] Handshake rejected from ${req.socket.remoteAddress}: ${parsed.error}`);
      ws.close(4001, parsed.error);
      return;
    }

    const { command, targetHost, targetPort, initialPayload } = parsed;

    // 1. TCP Tunneling
    if (command === 1) {
      handleTcp(ws, targetHost, targetPort, initialPayload);
    // 2. UDP Tunneling (DNS / VoIP / Gaming)
    } else if (command === 2) {
      handleUdp(ws, targetHost, targetPort, initialPayload);
    } else {
      console.warn(`[VLESS] Unsupported command ${command} from ${req.socket.remoteAddress}`);
      ws.close(1002, 'Unsupported command');
    }
  });

  ws.on('error', () => {});
});

// Start listening
server.listen(PORT, HOST, () => {
  console.log('==================================================');
  console.log(` VLESS WebSocket Server [${NODE_NAME}]`);
  console.log(` Listening on : ${HOST}:${PORT} (${HAS_TLS ? 'WSS/TLS' : 'WS/Plain'})`);
  console.log(` UUID         : ${PRIMARY_UUID}`);
  console.log(` Path         : ${WSS_PATH}`);
  console.log('==================================================');
});
