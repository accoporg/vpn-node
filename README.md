# VLESS over WebSocket Node.js Server

High-performance, RFC-compliant **VLESS v0 over WebSocket** server written in pure modern Node.js.

Designed to run seamlessly inside **Docker, Pterodactyl, BungeeHost, Bot-Hosting, Render**, or any cloud/container environment.

---

## Features

- **Standard VLESS v0 Protocol**: Works out of the box with **v2rayNG, V2Box, Streisand, Sing-box, Nekoray, Shadowrocket, Clash-Meta**.
- **Bidirectional Backpressure**: Automatic buffer drainage and pause/resume mechanisms for high-speed streaming without memory leaks.
- **Auto-TLS Detection**: Loads `cert.pem` and `key.pem` automatically if present for WSS/HTTPS; falls back to standard HTTP/WS when behind edge proxies (Cloudflare, Render).
- **Built-in Web Dashboard**: Visiting `http(s)://host:port/` displays real-time connection stats, node uptime, and a 1-click **"Copy VLESS Link"** button.
- **DNS Resilience**: Built-in fallback to DNS over HTTPS (DoH) for container hosts that block outbound UDP port 53.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `UUID` | `4ed3658d-7f0b-5e27-f826-f75d33f18f7a` | Client UUID (comma-separated for multiple users) |
| `PORT` | `3000` | Port to listen on (automatically uses container `$PORT` / `$SERVER_PORT`) |
| `HOST` | `0.0.0.0` | Bind address |
| `WSS_PATH` | `/` | WebSocket path (e.g. `/`, `/vless`) |
| `NODE_NAME` | `VLESS-Node` | Display name for subscription and web dashboard |

---

## Quick Start

```bash
# Install dependencies
npm install

# Start server
npm start
```
