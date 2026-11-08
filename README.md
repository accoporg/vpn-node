# WS-VPN Node Server (VPS & Render Compatible)

This server acts as an exit node for the WS-VPN network, bridging WebSocket traffic into arbitrary TCP connections with bidirectional backpressure control and token authentication.

It natively auto-detects whether it is running on a **Traditional VPS (e.g., Pterodactyl / Ubuntu)** or on a **Cloud PaaS (e.g., Render)**.

---

## Deploying on Render (render.com)

### Method 1: Deploy from Git Repo (Recommended)
1. Push this `server/` directory (or the VPN repo) to GitHub/GitLab.
2. In Render Dashboard, click **New +** -> **Web Service**.
3. Select your repository.
4. Configure the service:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: `Free` (or higher)
5. Under **Environment Variables**, add:
   - `NODE_ALIAS`: A unique name for your node (e.g., `ws-render-1`, `rd-us-1`)
   - `NODE_SECRET`: Your node registration secret (matches control plane)
   - `CONTROL_PLANE`: `https://cnct.accopture.top`
   - `KEEP_ALIVE`: `true` (keeps free-tier instance active)
6. Click **Deploy Web Service**.

### Method 2: Deploy with Docker
Render automatically detects the provided `Dockerfile`. Simply choose **Docker** as the environment.

---

## How Render Auto-Detection Works
- **Port**: Render injects `$PORT` (typically 10000). The node listens internally on `0.0.0.0:$PORT` in plain HTTP/WS.
- **Edge TLS**: Render terminates SSL at its cloud edge. The server automatically detects `RENDER_EXTERNAL_HOSTNAME`, registers port `443`, and enables `tls: true` on the control plane.
- **Keep-Alive**: When `KEEP_ALIVE=true` or when Render is detected, the server automatically self-pings its `/` health endpoint every 10 minutes to prevent Render free-tier idle spin-down.

---

## Bypassing Anti-VPN & Datacenter Blocks (Zero-Root Userspace WARP)

When accessing sites with aggressive anti-proxy filters (Cloudflare Turnstile, Netflix, banking sites), exit nodes hosted on Hetzner, M247, or Render can get flagged because of their datacenter ASN.

To solve this **without requiring root, `sudo`, or `apt`** inside preset containers (e.g. Pterodactyl):

Simply add to your `.env` or container environment variables:
```bash
ENABLE_WARP=true
```

### What Happens Automatically:
1. The server auto-downloads the standalone userspace `wireproxy` binary if missing.
2. It auto-registers a clean Cloudflare WARP account via API and generates WireGuard keys.
3. It launches the userspace SOCKS5 bridge on `127.0.0.1:40000`.
4. All outbound web requests exit through **Cloudflare's clean consumer IP pool**.
5. Zero `apt`, zero `sudo`, zero kernel modules required.

Alternatively, connect through an external residential proxy:
```bash
OUTBOUND_PROXY=socks5://user:pass@host:port
```

