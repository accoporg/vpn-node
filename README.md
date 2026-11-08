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
