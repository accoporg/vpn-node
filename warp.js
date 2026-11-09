import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import dns from 'node:dns';
import crypto from 'node:crypto';
import { spawn, execSync } from 'node:child_process';

// Force IPv4 DNS lookups first to prevent ENETUNREACH in Docker/Pterodactyl environments without IPv6 routing
try {
  dns.setDefaultResultOrder('ipv4first');
} catch {}

const WARP_DIR = path.resolve('.warp');
const WARP_BIN = path.join(WARP_DIR, 'wireproxy');
const WARP_CONF = path.join(WARP_DIR, 'warp.conf');
const SOCKS_PORT = parseInt(process.env.WARP_PORT || '40000', 10);
let warpProcess = null;

// -------------------------------------------------------------
// 1. Download & Extract wireproxy (No root / No apt needed)
// -------------------------------------------------------------
async function ensureWireproxyBinary() {
  const desiredVersion = process.env.WIREPROXY_VERSION || 'v1.0.7';
  const versionMarker = path.join(WARP_DIR, '.version');
  let currentVersion = '';
  if (fs.existsSync(versionMarker)) {
    try { currentVersion = fs.readFileSync(versionMarker, 'utf8').trim(); } catch {}
  }

  if (fs.existsSync(WARP_BIN) && currentVersion === desiredVersion) {
    try {
      fs.chmodSync(WARP_BIN, 0o755);
      return;
    } catch {}
  }

  if (!fs.existsSync(WARP_DIR)) {
    fs.mkdirSync(WARP_DIR, { recursive: true });
  }

  const arch = os.arch();
  let tarName = 'wireproxy_linux_amd64.tar.gz';
  if (arch === 'arm64' || arch === 'aarch64') {
    tarName = 'wireproxy_linux_arm64.tar.gz';
  }

  const downloadUrl = `https://github.com/octeep/wireproxy/releases/download/${desiredVersion}/${tarName}`;
  console.log(`[WARP] Downloading standalone wireproxy binary ${desiredVersion} (${arch}) from GitHub...`);

  const res = await fetch(downloadUrl, { redirect: 'follow' });
  if (!res.ok) {
    throw new Error(`Failed to download wireproxy: HTTP ${res.status}`);
  }

  const tarPath = path.join(WARP_DIR, tarName);
  const buffer = Buffer.from(await res.arrayBuffer());
  fs.writeFileSync(tarPath, buffer);

  console.log(`[WARP] Extracting wireproxy into ${WARP_DIR}...`);
  execSync(`tar -xzf "${tarPath}" -C "${WARP_DIR}"`);
  try { fs.unlinkSync(tarPath); } catch {}
  fs.chmodSync(WARP_BIN, 0o755);
  fs.writeFileSync(versionMarker, desiredVersion);
  console.log(`[WARP] Standalone wireproxy binary (${desiredVersion}) ready!`);
}

// -------------------------------------------------------------
// 2. Auto-Register Cloudflare WARP Account
// -------------------------------------------------------------
async function ensureWarpConfig({ controlPlane, nodeSecret } = {}) {
  if (fs.existsSync(WARP_CONF)) {
    return;
  }

  console.log('[WARP] Registering new Cloudflare WARP account via client API...');
  const keyPair = crypto.generateKeyPairSync('x25519');
  const pubKey = keyPair.publicKey.export({ type: 'spki', format: 'der' }).slice(-32).toString('base64');
  const privKey = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-32).toString('base64');

  const regPayload = {
    install_id: '',
    tos: new Date().toISOString(),
    key: pubKey,
    fcm_token: '',
    type: 'Android',
    model: 'Android',
    locale: 'en_US'
  };

  let data = null;

  // 1. Direct registration attempt with IPv4 preference
  try {
    const regRes = await fetch('https://api.cloudflareclient.com/v0a2158/reg', {
      method: 'POST',
      headers: {
        'User-Agent': 'okhttp/3.12.1',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(regPayload),
      signal: AbortSignal.timeout(10000)
    });

    if (regRes.ok) {
      data = await regRes.json();
    } else {
      console.warn(`[WARP] Direct registration returned HTTP ${regRes.status}`);
    }
  } catch (err) {
    const detail = err.cause ? (err.cause.code || err.cause.message) : err.message;
    console.warn(`[WARP] Direct registration failed (${detail}).`);
  }

  // 2. Fallback via Control Plane proxy if direct registration failed
  if (!data && controlPlane) {
    try {
      console.log(`[WARP] Attempting fallback via control plane (${controlPlane}/api/warp-register)...`);
      const headers = { 'Content-Type': 'application/json' };
      if (nodeSecret) headers['Authorization'] = `Bearer ${nodeSecret}`;

      const fallbackRes = await fetch(`${controlPlane}/api/warp-register`, {
        method: 'POST',
        headers,
        body: JSON.stringify(regPayload),
        signal: AbortSignal.timeout(10000)
      });

      if (fallbackRes.ok) {
        data = await fallbackRes.json();
        console.log('[WARP] Successfully registered WARP account via control plane proxy!');
      } else {
        console.warn(`[WARP] Control plane proxy registration returned HTTP ${fallbackRes.status}`);
      }
    } catch (fallbackErr) {
      console.warn(`[WARP] Control plane proxy registration failed: ${fallbackErr.message}`);
    }
  }

  if (!data) {
    throw new Error('WARP API registration failed (direct and control plane fallback both failed)');
  }

  const v4Address = data.config?.interface?.addresses?.v4 || '172.16.0.2';
  const peerKey = data.config?.peers?.[0]?.public_key || 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';
  const endpoint = '162.159.192.1:2408';

  const confContent = `[Interface]
PrivateKey = ${privKey}
Address = ${v4Address}/32
DNS = 1.1.1.1

[Peer]
PublicKey = ${peerKey}
Endpoint = ${endpoint}
AllowedIPs = 0.0.0.0/0
KeepAlive = 25

[Socks5]
BindAddress = 127.0.0.1:${SOCKS_PORT}
`;

  fs.writeFileSync(WARP_CONF, confContent);
  console.log(`[WARP] Successfully generated credentials and wrote ${WARP_CONF}`);
}

// -------------------------------------------------------------
// 3. Start Userspace WARP Process
// -------------------------------------------------------------
export async function initWarp(options = {}) {
  const controlPlane = options.controlPlane || process.env.CONTROL_PLANE;
  const nodeSecret = options.nodeSecret || process.env.NODE_SECRET;
  // Check if custom outbound proxy is provided
  if (process.env.OUTBOUND_PROXY) {
    try {
      const url = new URL(process.env.OUTBOUND_PROXY);
      console.log(`[OUTBOUND] Using custom outbound proxy: ${url.protocol}//${url.hostname}:${url.port}`);
      return {
        enabled: true,
        host: url.hostname,
        port: parseInt(url.port, 10),
        auth: (url.username && url.password) ? { user: url.username, pass: url.password } : null
      };
    } catch (e) {
      console.error('[OUTBOUND] Invalid OUTBOUND_PROXY URL:', e.message);
    }
  }

  const shouldEnable = process.env.ENABLE_WARP === 'true' ||
                       process.env.WARP === 'true' ||
                       process.env.USE_WARP === 'true';

  if (!shouldEnable) {
    return { enabled: false };
  }

  try {
    await ensureWireproxyBinary();
    await ensureWarpConfig({ controlPlane, nodeSecret });

    console.log(`[WARP] Starting userspace WARP daemon on 127.0.0.1:${SOCKS_PORT}...`);
    warpProcess = spawn(WARP_BIN, ['-c', WARP_CONF], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false
    });

    let lastError = '';
    warpProcess.stdout.on('data', (d) => {
      const msg = d.toString().trim();
      if (msg) console.log(`[WARP-LOG] ${msg}`);
    });

    warpProcess.stderr.on('data', (d) => {
      const msg = d.toString().trim();
      if (msg) {
        if (!msg.startsWith('DEBUG:')) {
          lastError = msg;
          console.error(`[WARP-ERR] ${msg}`);
        } else if (process.env.DEBUG === 'true') {
          console.log(`[WARP-DEBUG] ${msg}`);
        }
      }
    });

    warpProcess.on('error', (err) => {
      console.error('[WARP] Daemon process error:', err.message);
    });

    warpProcess.on('exit', (code, signal) => {
      if (code !== 0 && code !== null) {
        console.warn(`[WARP] Daemon exited with code ${code} / ${signal}. Reason: ${lastError || 'None reported'}`);
      }
    });

    // Wait for SOCKS5 port to accept connections (up to 7s)
    let ready = false;
    for (let i = 0; i < 70; i++) {
      try {
        await new Promise((resolve, reject) => {
          const s = net.connect({ host: '127.0.0.1', port: SOCKS_PORT }, () => {
            s.destroy();
            resolve();
          });
          s.on('error', reject);
        });
        ready = true;
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 100));
      }
    }

    if (!ready) {
      console.warn('[WARP] Warning: WARP SOCKS5 listener not ready yet. Outbound may fallback to direct.');
    } else {
      console.log(`[WARP] Connected! All outbound web traffic will exit via clean Cloudflare Consumer IP.`);
    }

    // Process shutdown cleanup
    const stopWarp = () => {
      if (warpProcess && !warpProcess.killed) {
        try { warpProcess.kill('SIGKILL'); } catch {}
      }
    };
    process.once('exit', stopWarp);
    process.once('SIGINT', stopWarp);
    process.once('SIGTERM', stopWarp);

    return {
      enabled: true,
      host: '127.0.0.1',
      port: SOCKS_PORT
    };
  } catch (err) {
    const detail = err.cause ? ` (${err.cause.code || err.cause.message})` : '';
    console.error(`[WARP] Initialization failed: ${err.message}${detail}`);
    console.warn('[WARP] Falling back to direct VPS outbound.');
    return { enabled: false };
  }
}

// -------------------------------------------------------------
// 4. Outbound Connection Dialer (Direct or SOCKS5)
// -------------------------------------------------------------
export function dialTarget({ targetHost, targetPort, outboundProxy, timeout = 12000 }) {
  if (!outboundProxy || !outboundProxy.enabled) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const socket = net.connect({ host: targetHost, port: targetPort });

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(new Error(`Direct TCP dial to ${targetHost}:${targetPort} timed out`));
        }
      }, timeout);

      socket.once('connect', () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve(socket);
        }
      });

      socket.once('error', (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
      });
    });
  }

  // Dial through SOCKS5 proxy
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = net.connect({ host: outboundProxy.host, port: outboundProxy.port, timeout }, () => {
      // 1. SOCKS5 Greeting: [VER=0x05, NMETHODS=1, METHOD=0x00]
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    let stage = 0; // 0: greeting, 1: connect reply

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new Error(`Outbound proxy connection to ${targetHost}:${targetPort} timed out`));
      }
    }, timeout);

    socket.on('data', function onData(chunk) {
      if (stage === 0) {
        if (chunk[0] !== 0x05 || chunk[1] !== 0x00) {
          settled = true;
          clearTimeout(timer);
          socket.destroy();
          return reject(new Error('Outbound SOCKS5 auth negotiation rejected'));
        }
        stage = 1;

        // 2. SOCKS5 CONNECT command
        const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(targetHost);
        let destBuf;
        if (isIpv4) {
          const octets = targetHost.split('.').map(Number);
          destBuf = Buffer.from([0x01, ...octets]);
        } else {
          const hostBytes = Buffer.from(targetHost, 'utf8');
          destBuf = Buffer.concat([Buffer.from([0x03, hostBytes.length]), hostBytes]);
        }

        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(targetPort, 0);

        socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), destBuf, portBuf]));
      } else if (stage === 1) {
        settled = true;
        clearTimeout(timer);
        socket.off('data', onData);

        if (chunk[0] !== 0x05 || chunk[1] !== 0x00) {
          socket.destroy();
          return reject(new Error(`Outbound SOCKS5 connect to ${targetHost}:${targetPort} failed (status ${chunk[1]})`));
        }

        // Handle any trailing application bytes sent in the same packet
        let headerLen = 4;
        if (chunk[3] === 0x01) headerLen = 10;
        else if (chunk[3] === 0x04) headerLen = 22;
        else if (chunk[3] === 0x03) headerLen = 4 + 1 + chunk[4] + 2;

        if (chunk.length > headerLen) {
          const extra = chunk.subarray(headerLen);
          socket.unshift(extra);
        }

        resolve(socket);
      }
    });

    socket.on('error', (err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(err);
      }
    });
  });
}
