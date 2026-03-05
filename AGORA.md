---
## Goal

Implement a web SSH client where:
- User accesses `http://localhost:8080/index.html`
- User inputs target host, port, username, and password
- Browser creates WebSocket connection to `wss://claw.603030.xyz:8443/websockify?host=$HOST&port=$PORT`
- The HTTP server (already running) proxies TCP byte stream through WebSocket
- Browser interprets SSH protocol and binds to xterm.js terminal
- User gets interactive SSH terminal in the browser

## Status: COMPLETE ✓

The WebSSH client is fully functional:
- SSH handshake (banner exchange, KEXINIT, DH key exchange, NEWKEYS)
- Encryption with AES-CTR
- Authentication with password
- Channel management (open, PTY, shell)
- Interactive terminal with xterm.js

## Files

- `/home/level/webssh/index.html` - Main HTML page with connection UI
- `/home/level/webssh/ssh.js` - SSH protocol implementation (~1150 lines)
- `/home/level/webssh/ws_proxy.py` - WebSocket proxy server

## Running Services

- HTTP server: `python3 -m http.server 8080` (PID check with `pgrep`)
- WebSocket proxy: Already running at `wss://claw.603030.xyz:8443`

## Usage

1. Open `http://localhost:8080/index.html` in browser
2. Enter SSH server details (host, port, username, password)
3. Click "Connect"
4. Interactive terminal appears - type commands!

## Key Implementation Details

- DH group14-sha256 for key exchange
- AES-CTR encryption with HMAC-SHA256 MAC
- Proper sequence number tracking for all packets
- mpint encoding for multi-precision integers
- Channel ID mapping (local vs remote)

## Notes

- Debug output is enabled by default (see `ssh.onDebug` in index.html)
- Remove debug callbacks for production use
