import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import dns from 'node:dns';
import { WebSocketServer } from 'ws';

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

    const regData = await regRes.json();
    if (regRes.ok) {
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
      console.error(`[REG] Registration failed (${regRes.status}):`, regData);
    }
  } catch (err) {
    console.error(`[REG] Registration error: ${err.message}`);
  }
}

// -------------------------------------------------------------
// 2. 60-Second Token Sync Loop
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

// Recurring 60s timer
if (NODE_SECRET) {
  setInterval(syncTokens, 60000);
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

wss.on('connection', (ws, req) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const clientToken = reqUrl.searchParams.get('token') || req.headers['x-auth-token'];
  const host = reqUrl.searchParams.get('host');
  const port = parseInt(reqUrl.searchParams.get('port'), 10);

  // Validate token if sync is active
  if (NODE_SECRET && validTokens.size > 0) {
    if (!clientToken || !validTokens.has(clientToken)) {
      console.warn(`[AUTH] Rejected client from ${req.socket.remoteAddress}: Invalid token.`);
      ws.close(4001, 'Unauthorized');
      return;
    }
  }

  if (!host || !port) {
    ws.close(1008, 'Missing host or port parameters');
    return;
  }

  const session = { ws, targetSocket: null, token: clientToken };
  activeSessions.add(session);

  let isCleanedUp = false;
  let drainInterval = null;
  let targetSocket = null;

  const cleanup = () => {
    if (isCleanedUp) return;
    isCleanedUp = true;
    if (drainInterval) clearInterval(drainInterval);
    activeSessions.delete(session);
    if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
    if (ws.readyState === ws.OPEN || ws.readyState === ws.CONNECTING) ws.close();
  };

  // Immediate WS lifecycle listeners to prevent unhandled errors
  ws.on('close', cleanup);
  ws.on('error', cleanup);

  // Connect to target destination
  targetSocket = net.connect({ host, port }, () => {
    if (isCleanedUp) {
      targetSocket.destroy();
      return;
    }

    // 1. WS -> TCP with Backpressure
    ws.on('message', (chunk) => {
      const canWrite = targetSocket.write(chunk);
      if (!canWrite && ws.pause) {
        ws.pause();
      }
    });

    targetSocket.on('drain', () => {
      if (ws.resume) ws.resume();
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

    // Check bufferedAmount periodically to resume TCP reads
    drainInterval = setInterval(() => {
      if (ws.bufferedAmount < 16 * 1024 && targetSocket.isPaused()) {
        targetSocket.resume();
      }
    }, 20);
  });

  session.targetSocket = targetSocket;
  targetSocket.on('close', cleanup);
  targetSocket.on('error', cleanup);
});

server.listen(PORT, HOST, async () => {
  console.log(`===============================================`);
  console.log(` WS-VPN Relay Node [${NODE_ALIAS}] listening on ${HOST}:${PORT}`);
  console.log(` External: ${PUBLIC_HOST || HOST}:${EXTERNAL_PORT} (TLS: ${EXTERNAL_TLS})`);
  console.log(` Platform: ${IS_RENDER ? 'Render Cloud (PaaS)' : 'Standalone VPS'}`);
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
