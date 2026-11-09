import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';
import { WebSocketServer } from 'ws';
import { initWarp, dialTarget } from './warp.js';

// Force IPv4 DNS lookups first to prevent ENETUNREACH in Docker/Pterodactyl environments without IPv6 routing
try {
  dns.setDefaultResultOrder('ipv4first');
} catch {}

let outboundProxy = null;

// Helpers for V2Ray / VLESS protocol compatibility
function tokenToUUID(token) {
  if (!token) return '';
  const clean = token.replace(/-/g, '');
  if (/^[0-9a-fA-F]{32}$/.test(clean.slice(0, 32))) {
    const h = clean.slice(0, 32).toLowerCase();
    return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20,32)}`;
  }
  const h = crypto.createHash('md5').update(token).digest('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20,32)}`;
}

function formatUUID(buf) {
  return [
    buf.subarray(0, 4).toString('hex'),
    buf.subarray(4, 6).toString('hex'),
    buf.subarray(6, 8).toString('hex'),
    buf.subarray(8, 10).toString('hex'),
    buf.subarray(10, 16).toString('hex')
  ].join('-');
}

// Automatically load configuration from .env or config.json if present
if (fs.existsSync('.env')) {
  try {
    const lines = fs.readFileSync('.env', 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
      if (idx !== -1) {
        const key = trimmed.slice(0, idx).trim();
        let val = trimmed.slice(idx + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        process.env[key] = val;
      }
    }
    console.log('[CONFIG] Successfully loaded environment from .env');
  } catch (err) {
    console.warn('[CONFIG] Error reading .env:', err.message);
  }
} else if (fs.existsSync('config.json')) {
  try {
    const cfg = JSON.parse(fs.readFileSync('config.json', 'utf8'));
    for (const [key, val] of Object.entries(cfg)) {
      process.env[key] = val;
    }
    console.log('[CONFIG] Successfully loaded configuration from config.json');
  } catch (err) {
    console.warn('[CONFIG] Error reading config.json:', err.message);
  }
}

// Configuration
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || process.argv[2] || '8080', 10);
const HOST = '0.0.0.0';
const CONTROL_PLANE = process.env.CONTROL_PLANE || 'https://cnct.accopture.top';
const NODE_SECRET = process.env.NODE_SECRET || null;
const NODE_ALIAS = process.env.NODE_ALIAS || 'ws-ro';
const REGISTER_FILE = path.resolve('.registered');

// TLS & Cloud Environment Auto-Detection
const CERT_FILE = process.env.SSL_CERT || path.resolve('cert.pem');
const KEY_FILE = process.env.SSL_KEY || path.resolve('key.pem');
const HAS_LOCAL_TLS = fs.existsSync(CERT_FILE) && fs.existsSync(KEY_FILE);

// Render PaaS detection
const IS_RENDER = process.env.RENDER === 'true' || Boolean(process.env.RENDER_SERVICE_ID) || Boolean(process.env.RENDER_EXTERNAL_HOSTNAME);
const PUBLIC_HOST = process.env.RENDER_EXTERNAL_HOSTNAME || process.env.PUBLIC_HOST || null;
const EXTERNAL_PORT = parseInt(process.env.EXTERNAL_PORT || (IS_RENDER ? '443' : PORT), 10);
const EXTERNAL_TLS = process.env.FORCE_TLS === 'true' || (IS_RENDER ? true : HAS_LOCAL_TLS);

// In-memory valid client tokens & active connections
let validTokens = new Set();
const activeSessions = new Set(); // { ws, targetSocket, token }

// -------------------------------------------------------------
// 1. First-Boot / Reconfiguration Self-Registration
// -------------------------------------------------------------
async function registerNode() {
  if (!NODE_SECRET) {
    console.log('[REG] NODE_SECRET not set, skipping registration.');
    return;
  }

  // Check if already registered with matching config
  if (fs.existsSync(REGISTER_FILE)) {
    try {
      const existing = JSON.parse(fs.readFileSync(REGISTER_FILE, 'utf8'));
      if (
        existing.tls === EXTERNAL_TLS &&
        existing.alias === NODE_ALIAS &&
        existing.port === EXTERNAL_PORT &&
        existing.host === (PUBLIC_HOST || `${NODE_ALIAS}.cnct.accopture.top`)
      ) {
        console.log('[REG] Node already registered with matching config. Skipping.');
        return;
      }
    } catch {}
  }

  console.log(`[REG] Registering node '${NODE_ALIAS}' (External TLS: ${EXTERNAL_TLS}, Port: ${EXTERNAL_PORT}) with control plane: ${CONTROL_PLANE}...`);
  try {
    const isPrivateIP = (ip) => {
      if (!ip) return true;
      return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.)/.test(ip.trim());
    };

    // Detect public IP (env PUBLIC_IP first if non-private)
    let publicIp = (process.env.PUBLIC_IP && !isPrivateIP(process.env.PUBLIC_IP)) ? process.env.PUBLIC_IP.trim() : null;

    // If PUBLIC_HOST is available (e.g. Render external hostname), resolve its public IP
    if (!publicIp && PUBLIC_HOST) {
      try {
        const lookupRes = await dns.promises.lookup(PUBLIC_HOST);
        if (lookupRes && lookupRes.address && !isPrivateIP(lookupRes.address)) {
          publicIp = lookupRes.address;
        }
      } catch {}
    }

    if (!publicIp) {
      try {
        const res = await fetch('https://icanhazip.com', { signal: AbortSignal.timeout(5000) });
        const detected = (await res.text()).trim();
        if (!isPrivateIP(detected)) publicIp = detected;
      } catch {}
    }

    if (!publicIp) {
      try {
        const res = await fetch('https://api.ipify.org', { signal: AbortSignal.timeout(5000) });
        const detected = (await res.text()).trim();
        if (!isPrivateIP(detected)) publicIp = detected;
      } catch {}
    }

    if (!publicIp) {
      console.error('[REG] Could not detect public IP. Skipping registration.');
      return;
    }

    console.log(`[REG] Detected public IP: ${publicIp}, External Port: ${EXTERNAL_PORT}, Host: ${PUBLIC_HOST || `${NODE_ALIAS}.cnct.accopture.top`}`);

    const regRes = await fetch(`${CONTROL_PLANE}/api/register`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${NODE_SECRET}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        alias: NODE_ALIAS,
        ip: publicIp,
        port: EXTERNAL_PORT,
        tls: EXTERNAL_TLS,
        host: PUBLIC_HOST
      }),
      signal: AbortSignal.timeout(10000)
    });

    let regData;
    const contentType = regRes.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      regData = await regRes.json();
    } else {
      const text = await regRes.text();
      regData = { error: `Server returned HTTP ${regRes.status} (non-JSON): ${text.slice(0, 80).replace(/\s+/g, ' ')}...` };
    }

    if (regRes.ok && regData && regData.domain) {
      fs.writeFileSync(REGISTER_FILE, JSON.stringify({
        ...regData,
        tls: EXTERNAL_TLS,
        alias: NODE_ALIAS,
        port: EXTERNAL_PORT,
        host: PUBLIC_HOST || regData.domain
      }, null, 2));
      console.log(`[REG] Success! Node registered as: ${regData.domain} (${publicIp}:${EXTERNAL_PORT}, TLS: ${EXTERNAL_TLS})`);
      if (regData.dns) console.log(`[REG] Cloudflare DNS status: ${regData.dns}`);
    } else {
      console.error(`[REG] Registration failed (${regRes.status}):`, regData.error || regData);
    }
  } catch (err) {
    console.error(`[REG] Registration error: ${err.message}`);
  }
}

// -------------------------------------------------------------
// 2. 60-Second Token Sync Loop & Auto-Registration Retry
// -------------------------------------------------------------
async function syncTokens() {
  if (!NODE_SECRET) return;

  try {
    const res = await fetch(`${CONTROL_PLANE}/api/tokens`, {
      headers: { 'Authorization': `Bearer ${NODE_SECRET}` },
      signal: AbortSignal.timeout(7000)
    });

    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.tokens)) {
        validTokens = new Set(data.tokens);

        // Check active sessions: drop any whose token is no longer valid
        for (const session of activeSessions) {
          if (!validTokens.has(session.token)) {
            console.warn(`[AUTH] Dropping connection: Token '${session.token}' was revoked.`);
            session.ws.close(4001, 'Token revoked');
            if (session.targetSocket) session.targetSocket.destroy();
            activeSessions.delete(session);
          }
        }
      }
    }
  } catch {
    // If control plane is briefly unreachable, keep existing cache
  }
}

// Recurring timer: token sync every 60s, registration retry every 30s until successful
if (NODE_SECRET) {
  setInterval(syncTokens, 60000);
  setInterval(async () => {
    if (!fs.existsSync(REGISTER_FILE)) {
      await registerNode();
    }
  }, 30000);
}

// -------------------------------------------------------------
// 3. Server Setup (HTTPS/WSS if certs exist, otherwise HTTP/WS)
// -------------------------------------------------------------
const requestHandler = (req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'online',
    alias: NODE_ALIAS,
    tls: EXTERNAL_TLS,
    localTls: HAS_LOCAL_TLS,
    platform: IS_RENDER ? 'render' : 'standalone',
    warp: Boolean(outboundProxy?.enabled),
    host: PUBLIC_HOST,
    port: EXTERNAL_PORT,
    activeSessions: activeSessions.size,
    tokensLoaded: validTokens.size,
    uptime: Math.floor(process.uptime())
  }));
};

let server;
if (HAS_LOCAL_TLS && !IS_RENDER && process.env.FORCE_HTTP !== 'true') {
  console.log('[TLS] Loading SSL certificate from cert.pem and key.pem...');
  server = https.createServer({
    cert: fs.readFileSync(CERT_FILE),
    key: fs.readFileSync(KEY_FILE),
    minVersion: 'TLSv1.2'
  }, requestHandler);
  console.log('[TLS] HTTPS and WSS (Encrypted) enabled!');
} else {
  server = http.createServer(requestHandler);
  if (IS_RENDER) {
    console.log('[RENDER] Render environment detected. Listening on plain HTTP/WS internally; TLS terminated by Render edge on port 443.');
  } else {
    console.log('[TLS] cert.pem/key.pem not found. Running in plain HTTP/WS mode.');
  }
}

server.on('error', (err) => {
  console.error('[SERVER] Fatal server error:', err.message);
});

const wss = new WebSocketServer({ server });

// -------------------------------------------------------------
// Native CLI Client Connection Handler (vpn connect <alias>)
// -------------------------------------------------------------
function handleCliClient(ws, req, clientToken, host, port) {
  // Validate token if sync is active
  if (NODE_SECRET && validTokens.size > 0) {
    if (!clientToken || !validTokens.has(clientToken)) {
      console.warn(`[AUTH] Rejected client from ${req.socket.remoteAddress}: Invalid token.`);
      ws.close(4001, 'Unauthorized');
      return;
    }
  }

  const session = { ws, targetSocket: null, token: clientToken };
  activeSessions.add(session);

  let isCleanedUp = false;
  let drainInterval = null;
  let targetSocket = null;
  const earlyChunks = [];

  const onEarlyMessage = (chunk) => {
    earlyChunks.push(chunk);
  };
  ws.on('message', onEarlyMessage);

  const cleanup = () => {
    if (isCleanedUp) return;
    isCleanedUp = true;
    ws.off('message', onEarlyMessage);
    earlyChunks.length = 0;
    if (drainInterval) clearInterval(drainInterval);
    activeSessions.delete(session);
    if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
    if (ws.readyState === ws.OPEN || ws.readyState === ws.CONNECTING) ws.close();
  };

  ws.on('close', cleanup);
  ws.on('error', cleanup);

  // Connect to target destination (Direct or via Cloudflare WARP / Outbound SOCKS5)
  dialTarget({ targetHost: host, targetPort: port, outboundProxy })
    .then((sock) => {
      if (isCleanedUp) {
        sock.destroy();
        return;
      }
      targetSocket = sock;
      session.targetSocket = targetSocket;
      targetSocket.on('close', cleanup);
      targetSocket.on('error', cleanup);

      ws.off('message', onEarlyMessage);

      // Flush all buffered early chunks (e.g. TLS Client Hello)
      for (const chunk of earlyChunks) {
        targetSocket.write(chunk);
      }
      earlyChunks.length = 0;

      // 1. WS -> TCP with Backpressure
      ws.on('message', (chunk) => {
        const canWrite = targetSocket.write(chunk);
        if (!canWrite && ws._socket) ws._socket.pause();
      });

      targetSocket.on('drain', () => {
        if (ws._socket) ws._socket.resume();
      });

      // 2. TCP -> WS with Backpressure
      targetSocket.on('data', (chunk) => {
        if (ws.readyState === ws.OPEN) {
          ws.send(chunk);
          if (ws.bufferedAmount > 64 * 1024) {
            targetSocket.pause();
          }
        }
      });

      drainInterval = setInterval(() => {
        if (ws.bufferedAmount < 16 * 1024 && targetSocket.isPaused()) {
          targetSocket.resume();
        }
      }, 20);
    })
    .catch((err) => {
      console.warn(`[DIAL] Failed to reach ${host}:${port}: ${err.message}`);
      cleanup();
    });
}

// -------------------------------------------------------------
// VLESS Mobile Protocol Handler (v2rayNG, V2Box, Streisand, Shadowrocket, Sing-box)
// -------------------------------------------------------------
function handleVlessClient(ws, req) {
  let isCleanedUp = false;
  let targetSocket = null;
  let udpSocket = null;
  let drainInterval = null;
  const session = { ws, targetSocket: null, token: 'vless-client' };
  activeSessions.add(session);

  const cleanup = () => {
    if (isCleanedUp) return;
    isCleanedUp = true;
    if (drainInterval) clearInterval(drainInterval);
    activeSessions.delete(session);
    if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
    if (udpSocket) {
      try { udpSocket.close(); } catch {}
    }
    if (ws.readyState === ws.OPEN || ws.readyState === ws.CONNECTING) ws.close();
  };

  ws.on('close', cleanup);
  ws.on('error', cleanup);

  // Wait for initial binary VLESS request frame
  ws.once('message', async (buffer) => {
    try {
      if (!Buffer.isBuffer(buffer)) buffer = Buffer.from(buffer);
      if (buffer.length < 24) {
        ws.close(1002, 'VLESS header too short');
        return;
      }

      const version = buffer[0];
      if (version !== 0) {
        ws.close(1002, 'Unsupported VLESS version');
        return;
      }

      const clientUuid = formatUUID(buffer.subarray(1, 17));

      // Authenticate UUID against synced tokens
      if (NODE_SECRET && validTokens.size > 0) {
        let matched = false;
        for (const tok of validTokens) {
          if (tokenToUUID(tok) === clientUuid || tok === clientUuid) {
            matched = true;
            break;
          }
        }
        if (!matched) {
          console.warn(`[VLESS] Rejected unauthorized UUID ${clientUuid} from ${req.socket.remoteAddress}`);
          ws.close(4001, 'Unauthorized UUID');
          return;
        }
      }

      const addonsLen = buffer[17];
      let cursor = 18 + addonsLen;
      if (buffer.length < cursor + 4) {
        ws.close(1002, 'Invalid VLESS command section');
        return;
      }

      const command = buffer[cursor]; // 1 = TCP, 2 = UDP
      const targetPort = buffer.readUInt16BE(cursor + 1);
      const addressType = buffer[cursor + 3];
      cursor += 4;

      let targetHost = '';
      if (addressType === 1) { // IPv4
        if (buffer.length < cursor + 4) return ws.close(1002, 'Invalid IPv4 address');
        targetHost = `${buffer[cursor]}.${buffer[cursor+1]}.${buffer[cursor+2]}.${buffer[cursor+3]}`;
        cursor += 4;
      } else if (addressType === 2) { // Domain
        const dLen = buffer[cursor];
        cursor += 1;
        if (buffer.length < cursor + dLen) return ws.close(1002, 'Invalid domain name');
        targetHost = buffer.subarray(cursor, cursor + dLen).toString('utf8');
        cursor += dLen;
      } else if (addressType === 3) { // IPv6
        if (buffer.length < cursor + 16) return ws.close(1002, 'Invalid IPv6 address');
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(buffer.readUInt16BE(cursor + i).toString(16));
        targetHost = parts.join(':');
        cursor += 16;
      } else {
        ws.close(1002, 'Unknown address type');
        return;
      }

      const initialPayload = buffer.subarray(cursor);

      // Send VLESS response header (version 0, addons length 0)
      ws.send(Buffer.from([0x00, 0x00]));

      // 1. TCP Tunneling
      if (command === 1) {
        const earlyChunks = [];
        const onEarlyMessage = (chunk) => earlyChunks.push(chunk);
        ws.on('message', onEarlyMessage);

        const sock = await dialTarget({ targetHost, targetPort, outboundProxy });
        if (isCleanedUp) {
          sock.destroy();
          return;
        }
        targetSocket = sock;
        session.targetSocket = targetSocket;
        targetSocket.on('close', cleanup);
        targetSocket.on('error', cleanup);

        if (initialPayload.length > 0) {
          targetSocket.write(initialPayload);
        }

        ws.off('message', onEarlyMessage);
        for (const chunk of earlyChunks) {
          targetSocket.write(chunk);
        }
        earlyChunks.length = 0;

        ws.on('message', (chunk) => {
          const canWrite = targetSocket.write(chunk);
          if (!canWrite && ws._socket) ws._socket.pause();
        });

        targetSocket.on('drain', () => {
          if (ws._socket) ws._socket.resume();
        });

        targetSocket.on('data', (chunk) => {
          if (ws.readyState === ws.OPEN) {
            ws.send(chunk);
            if (ws.bufferedAmount > 64 * 1024) targetSocket.pause();
          }
        });

        drainInterval = setInterval(() => {
          if (ws.bufferedAmount < 16 * 1024 && targetSocket.isPaused()) {
            targetSocket.resume();
          }
        }, 20);

      // 2. UDP Tunneling (DNS / VoIP / Gaming)
      } else if (command === 2) {
        udpSocket = dgram.createSocket('udp4');
        udpSocket.on('error', cleanup);
        udpSocket.on('message', (msg) => {
          if (ws.readyState === ws.OPEN) {
            const lenBuf = Buffer.alloc(2);
            lenBuf.writeUInt16BE(msg.length, 0);
            ws.send(Buffer.concat([lenBuf, msg]));
          }
        });

        const forwardUdp = (chunk) => {
          let off = 0;
          while (off + 2 < chunk.length) {
            const pLen = chunk.readUInt16BE(off);
            off += 2;
            if (off + pLen <= chunk.length) {
              const pkt = chunk.subarray(off, off + pLen);
              udpSocket.send(pkt, targetPort, targetHost);
              off += pLen;
            } else {
              break;
            }
          }
        };

        if (initialPayload.length > 2) {
          forwardUdp(initialPayload);
        }

        ws.on('message', forwardUdp);

      } else {
        ws.close(1003, 'Unsupported VLESS command');
      }

    } catch (err) {
      console.warn(`[VLESS] Error handling client: ${err.message}`);
      cleanup();
    }
  });
}

wss.on('connection', (ws, req) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const clientToken = reqUrl.searchParams.get('token') || req.headers['x-auth-token'];
  const host = reqUrl.searchParams.get('host');
  const port = parseInt(reqUrl.searchParams.get('port'), 10);

  // If host and port are given in search parameters, handle as native CLI client
  if (host && port) {
    handleCliClient(ws, req, clientToken, host, port);
    return;
  }

  // Otherwise, handle as standard VLESS client (v2rayNG, V2Box, Streisand, etc.)
  handleVlessClient(ws, req);
});

server.listen(PORT, HOST, async () => {
  // Initialize Userspace WARP / Outbound Proxy if enabled
  outboundProxy = await initWarp({ controlPlane: CONTROL_PLANE, nodeSecret: NODE_SECRET });

  console.log(`===============================================`);
  console.log(` WS-VPN Relay Node [${NODE_ALIAS}] listening on ${HOST}:${PORT}`);
  console.log(` External: ${PUBLIC_HOST || HOST}:${EXTERNAL_PORT} (TLS: ${EXTERNAL_TLS})`);
  console.log(` Platform: ${IS_RENDER ? 'Render Cloud (PaaS)' : 'Standalone VPS'}`);
  console.log(` Outbound: ${outboundProxy?.enabled ? `Proxied via ${outboundProxy.host}:${outboundProxy.port} (Clean Consumer IP)` : 'Direct VPS Egress'}`);
  console.log(` Control Plane: ${CONTROL_PLANE}`);
  console.log(`===============================================`);
  if (NODE_SECRET) {
    await syncTokens();
  }
  await registerNode();

  // Keep-alive heartbeat for Render free-tier (prevents idle spin-down)
  if (IS_RENDER || process.env.KEEP_ALIVE === 'true') {
    const keepAliveUrl = process.env.RENDER_EXTERNAL_URL || (PUBLIC_HOST ? `https://${PUBLIC_HOST}` : null);
    if (keepAliveUrl) {
      console.log(`[RENDER] Keep-alive active: pinging ${keepAliveUrl} every 10 minutes.`);
      setInterval(() => {
        fetch(`${keepAliveUrl}/`).catch(() => {});
      }, 10 * 60 * 1000);
    }
  }
});
