# WebSSH

A pure JavaScript SSH client that runs entirely in the browser, enabling SSH connections without requiring any server-side SSH proxy.

## Features

- **Pure Browser Implementation**: Complete SSH protocol implementation in JavaScript
- **Multiple Authentication Methods**:
  - Password authentication
  - Public key authentication (RSA, ECDSA, Ed25519)
- **Interactive Terminal**: Full terminal emulation using xterm.js
- **Secure Encryption**: AES-CTR encryption with HMAC-SHA256 for integrity
- **Key Exchange**: Diffie-Hellman Group 14 SHA-256

## Quick Start

1. Start a local HTTP server:
   ```bash
   python3 -m http.server 8080
   ```

2. Open `http://localhost:8080` in your browser

3. Enter connection details:
   - Host: Target SSH server IP
   - Port: SSH port (default 22)
   - Username: SSH username
   - Choose authentication method (password or key)

4. For key authentication, select your private key file (supports OpenSSH format)

## Architecture

### Components

- **`index.html`**: Web UI with connection panel and terminal
- **`ssh.js`**: Complete SSH protocol implementation
- **`ws_proxy.py`**: Optional WebSocket-to-TCP proxy (for reference)

### SSH Protocol Flow

```
Client                          Server
  |                               |
  |------- SSH Banner ----------->|
  |<------ SSH Banner ------------|
  |------- KEXINIT -------------->|
  |<------ KEXINIT ---------------|
  |------- KEXDH_INIT ----------->|
  |<------ KEXDH_REPLY ----------|
  |------- NEWKEYS -------------->|
  |<------ NEWKEYS ---------------|
  |                               |
  |===== Encrypted Transport =====|
  |                               |
  |------- SERVICE_REQUEST ------>|
  |<------ SERVICE_ACCEPT --------|
  |------- USERAUTH_REQUEST ----->|
  |<------ USERAUTH_SUCCESS ------|
  |------- CHANNEL_OPEN --------->|
  |<------ CHANNEL_OPEN_CONF ----|
  |------- PTY-REQUEST ---------->|
  |------- SHELL-REQUEST -------->|
  |<------ CHANNEL_SUCCESS -------|
  |                               |
  |======= Interactive Shell =====|
```

### Supported Algorithms

| Type | Algorithms |
|------|------------|
| Key Exchange | diffie-hellman-group14-sha256 |
| Encryption | aes256-ctr |
| MAC | hmac-sha2-256 |
| Public Key | ssh-rsa, ecdsa-sha2-*, ssh-ed25519 |

## Key File Support

Supports OpenSSH private key format:
- RSA keys
- ECDSA keys (nistp256, nistp384, nistp521)
- Ed25519 keys

### Example Key Generation

```bash
# Generate Ed25519 key
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519

# Generate RSA key
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa

# Generate ECDSA key
ssh-keygen -t ecdsa -b 256 -f ~/.ssh/id_ecdsa
```

## WebSocket Proxy

The client connects through a WebSocket proxy that bridges WebSocket to raw TCP:

```
Browser <--WebSocket--> Proxy <--TCP--> SSH Server
```

Default proxy URL: `wss://claw.603030.xyz:8443/websockify`

## Technical Details

### Packet Structure

**Unencrypted Packet:**
```
uint32    packet_length
byte      padding_length
byte[n1]  payload
byte[n2]  random padding
```

**Encrypted Packet:**
```
byte[n]   encrypted packet (length + padding_length + payload + padding)
byte[m]   MAC
```

### Key Derivation

Keys are derived from the shared secret K and exchange hash H:
```
IV_C2S  = HASH(K || H || "A" || session_id)
IV_S2C  = HASH(K || H || "B" || session_id)
Enc_C2S = HASH(K || H || "C" || session_id)
Enc_S2C = HASH(K || H || "D" || session_id)
MAC_C2S = HASH(K || H || "E" || session_id)
MAC_S2C = HASH(K || H || "F" || session_id)
```

### Public Key Authentication

1. Client sends `USERAUTH_REQUEST` with public key blob and `want_reply=false`
2. Server responds with `USERAUTH_PK_OK` if key is acceptable
3. Client signs: `session_id || USERAUTH_REQUEST` and sends with signature
4. Server verifies signature and responds with `USERAUTH_SUCCESS` or `USERAUTH_FAILURE`

## Dependencies

- [xterm.js](https://xtermjs.org/) - Terminal emulator
- [TweetNaCl](https://tweetnacl.js.org/) - Ed25519 signing (loaded from CDN)

## Browser Compatibility

Tested on:
- Chrome/Chromium 90+
- Firefox 90+
- Safari 15+

Requires:
- Web Crypto API
- WebSocket
- TextEncoder/TextDecoder

## Security Considerations

- Private keys are handled entirely in browser memory
- No server-side storage of credentials
- Uses strong encryption (AES-256-CTR)
- HMAC-SHA256 for message integrity
- Keys are cleared when page is closed

## Limitations

- Single channel support (one shell session)
- No port forwarding
- No X11 forwarding
- No agent forwarding
- Encrypted private keys not supported (use unencrypted keys)

## License

MIT License

## Acknowledgments

- [xterm.js](https://xtermjs.org/) for the excellent terminal emulator
- [TweetNaCl.js](https://tweetnacl.js.org/) for Ed25519 cryptography
- [RFC 4251-4254](https://datatracker.ietf.org/doc/html/rfc4251) for SSH protocol specification
- [RFC 8709](https://datatracker.ietf.org/doc/html/rfc8709) for Ed25519 in SSH