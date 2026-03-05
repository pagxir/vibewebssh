const SSH_MSG_DISCONNECT = 1;
const SSH_MSG_IGNORE = 2;
const SSH_MSG_UNIMPLEMENTED = 3;
const SSH_MSG_DEBUG = 4;
const SSH_MSG_SERVICE_REQUEST = 5;
const SSH_MSG_SERVICE_ACCEPT = 6;
const SSH_MSG_KEXINIT = 20;
const SSH_MSG_NEWKEYS = 21;
const SSH_MSG_KEXDH_INIT = 30;
const SSH_MSG_KEXDH_REPLY = 31;
const SSH_MSG_USERAUTH_REQUEST = 50;
const SSH_MSG_USERAUTH_FAILURE = 51;
const SSH_MSG_USERAUTH_SUCCESS = 52;
const SSH_MSG_USERAUTH_BANNER = 53;
const SSH_MSG_USERAUTH_PK_OK = 60;
const SSH_MSG_GLOBAL_REQUEST = 80;
const SSH_MSG_REQUEST_SUCCESS = 81;
const SSH_MSG_REQUEST_FAILURE = 82;
const SSH_MSG_CHANNEL_OPEN = 90;
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
const SSH_MSG_CHANNEL_WINDOW_ADJUST = 94;
const SSH_MSG_CHANNEL_DATA = 94;
const SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
const SSH_MSG_CHANNEL_EOF = 96;
const SSH_MSG_CHANNEL_CLOSE = 97;
const SSH_MSG_CHANNEL_REQUEST = 98;
const SSH_MSG_CHANNEL_SUCCESS = 99;
const SSH_MSG_CHANNEL_FAILURE = 100;

const SSH_SERVICE_USERAUTH = 'ssh-userauth';
const SSH_SERVICE_CONNECTION = 'ssh-connection';

const SSH_AUTH_TYPE_NONE = 'none';
const SSH_AUTH_TYPE_PASSWORD = 'password';
const SSH_AUTH_TYPE_PUBLICKEY = 'publickey';

const SSH_CHANNEL_TYPE_SESSION = 'session';

const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
const SSH_DISCONNECT_PROTOCOL_ERROR = 2;
const SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
const SSH_DISCONNECT_RESERVED = 4;
const SSH_DISCONNECT_MAC_ERROR = 5;
const SSH_DISCONNECT_COMPRESSION_ERROR = 6;
const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;

class SSHPacket {
    constructor() {
        this.buffer = new Uint8Array(0);
        this.offset = 0;
    }

    reset() {
        this.buffer = new Uint8Array(0);
        this.offset = 0;
    }

    static from(data) {
        const pkt = new SSHPacket();
        pkt.buffer = new Uint8Array(data);
        return pkt;
    }

    readByte() {
        return this.buffer[this.offset++];
    }

    readBoolean() {
        return this.readByte() !== 0;
    }

    readUint32() {
        const val = ((this.buffer[this.offset] << 24) |
                     (this.buffer[this.offset + 1] << 16) |
                     (this.buffer[this.offset + 2] << 8) |
                     this.buffer[this.offset + 3]);
        this.offset += 4;
        return val >>> 0;
    }

    readUint64() {
        const hi = this.readUint32();
        const lo = this.readUint32();
        return [hi, lo];
    }

    readString() {
        const len = this.readUint32();
        const str = this.buffer.slice(this.offset, this.offset + len);
        this.offset += len;
        return str;
    }

    readStringText() {
        const bytes = this.readString();
        return new TextDecoder().decode(bytes);
    }

    readMPInt() {
        const bytes = this.readString();
        return bytes;
    }

    available() {
        return this.buffer.length - this.offset;
    }

    peekByte() {
        return this.buffer[this.offset];
    }
}

class SSHBuffer {
    constructor() {
        this.chunks = [];
        this.length = 0;
    }

    append(data) {
        if (data instanceof Uint8Array) {
            this.chunks.push(data);
        } else {
            this.chunks.push(new Uint8Array(data));
        }
        this.length += data.length;
    }

    appendByte(b) {
        this.chunks.push(new Uint8Array([b]));
        this.length += 1;
    }

    appendInt32(val) {
        const b = new Uint8Array(4);
        b[0] = (val >> 24) & 0xff;
        b[1] = (val >> 16) & 0xff;
        b[2] = (val >> 8) & 0xff;
        b[3] = val & 0xff;
        this.chunks.push(b);
        this.length += 4;
    }

    appendString(str) {
        const bytes = new TextEncoder().encode(str);
        this.appendInt32(bytes.length);
        this.append(bytes);
    }

    appendBuffer(buf) {
        this.appendInt32(buf.length);
        this.append(buf);
    }

    prependInt32(val) {
        const b = new Uint8Array(4);
        b[0] = (val >> 24) & 0xff;
        b[1] = (val >> 16) & 0xff;
        b[2] = (val >> 8) & 0xff;
        b[3] = val & 0xff;
        this.chunks.unshift(b);
        this.length += 4;
    }

    toUint8Array() {
        const result = new Uint8Array(this.length);
        let offset = 0;
        for (const chunk of this.chunks) {
            result.set(chunk, offset);
            offset += chunk.length;
        }
        return result;
    }
}

function getRandomBytes(n) {
    const bytes = new Uint8Array(n);
    crypto.getRandomValues(bytes);
    return bytes;
}

async function computeSHA256(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
}

async function computeHMACSHA256(key, data) {
    const cryptoKey = await crypto.subtle.importKey(
        'raw', key,
        { name: 'HMAC', hash: 'SHA-256' },
        false, ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
    return new Uint8Array(signature);
}

function arrayToHex(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToArray(hex) {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        arr[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return arr;
}

const MODULUS_P = hexToArray('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF');

function modPow(base, exp, mod) {
    let result = 1n;
    let b = base % mod;
    let e = exp;
    
    while (e > 0n) {
        if (e & 1n) {
            result = (result * b) % mod;
        }
        e >>= 1n;
        b = (b * b) % mod;
    }
    
    return result;
}

function bytesToBigInt(bytes) {
    let hex = '0x';
    for (const b of bytes) {
        hex += b.toString(16).padStart(2, '0');
    }
    return BigInt(hex);
}

function bigIntToBytes(bi) {
    let hex = bi.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    return hexToArray(hex);
}

function bigIntToBytesFixed(bi, len) {
    let hex = bi.toString(16);
    while (hex.length < len * 2) hex = '0' + hex;
    return hexToArray(hex.slice(-len * 2));
}

function bigIntToMpint(bi) {
    let bytes = bigIntToBytes(bi);
    if (bytes[0] & 0x80) {
        const result = new Uint8Array(bytes.length + 1);
        result[0] = 0;
        result.set(bytes, 1);
        return result;
    }
    return bytes;
}

class AESCounter {
    constructor(key, iv) {
        this.key = key;
        this.counter = new Uint8Array(16);
        this.counter.set(iv.slice(0, 16));
        this.cipher = null;
    }

    async init() {
        this.cipher = await crypto.subtle.importKey(
            'raw', this.key,
            { name: 'AES-CTR' },
            false, ['encrypt', 'decrypt']
        );
    }

    saveState() {
        return new Uint8Array(this.counter);
    }

    restoreState(state) {
        this.counter.set(state);
    }

    async process(data) {
        const counterCopy = new Uint8Array(this.counter);
        
        const result = await crypto.subtle.encrypt(
            { name: 'AES-CTR', counter: counterCopy, length: 128 },
            this.cipher,
            data
        );
        
        const numBlocks = Math.ceil(data.length / 16);
        this.incrementCounter(numBlocks);
        
        return new Uint8Array(result);
    }

    incrementCounter(numBlocks) {
        for (let i = 0; i < numBlocks; i++) {
            for (let j = 15; j >= 0; j--) {
                this.counter[j]++;
                if (this.counter[j] !== 0) break;
            }
        }
    }

    async decrypt(data) {
        return this.process(data);
    }

    async encrypt(data) {
        return this.process(data);
    }
}

class SSHConnection {
    constructor(ws) {
        this.ws = ws;
        this.state = 'keyinit';
        this.kex = null;
        this.serverKex = null;
        this.serverVersion = null;
        this.sessionId = null;
        this.outgoingCipher = null;
        this.incomingCipher = null;
        this.outgoingMac = null;
        this.incomingMac = null;
        this.incomingCompression = null;
        this.outgoingCompression = null;
        this.localChannelId = 0;
        this.channels = new Map();
        this.packet = new SSHPacket();
        this.packetLen = 0;
        this.paddingLen = 0;
        this.readBuffer = new Uint8Array(0);
        this.authenticated = false;
        this.authFailed = false;
        this.serviceAccepted = false;
        this.shellChannel = null;
        this.outgoingSeq = 0;
        this.incomingSeq = 0;
        this.onData = null;
        this.onClose = null;
        this.onDebug = null;
    }

    debug(msg) {
        if (this.onDebug) this.onDebug(msg);
        console.log('[SSH]', msg);
    }

    async connect() {
        this.ws.binaryType = 'arraybuffer';
        this.state = 'banner';
        
        this.debug(`WebSocket initial state: ${this.ws.readyState} (CONNECTING=0, OPEN=1, CLOSING=2, CLOSED=3)`);
        
        this.ws.onmessage = (event) => {
            const data = new Uint8Array(event.data);
            this.debug(`WS received ${data.length} bytes, state: ${this.state}`);
            console.log('WS.onmessage:', data.length, 'bytes');
            this.handleData(data);
        };
        
        this.ws.onclose = (event) => {
            this.debug(`WebSocket closed: code=${event.code}, reason=${event.reason}`);
            if (this.onClose) this.onClose();
        };
        
        this.ws.onerror = (error) => {
            this.debug(`WebSocket error: ${error}`);
            console.error('WebSocket error:', error);
        };
        
        if (this.ws.readyState !== WebSocket.OPEN) {
            this.debug('Waiting for WebSocket to open...');
            await new Promise((resolve, reject) => {
                const onOpen = () => {
                    this.ws.removeEventListener('open', onOpen);
                    this.ws.removeEventListener('error', onError);
                    this.debug('WebSocket opened');
                    resolve();
                };
                const onError = (e) => {
                    this.ws.removeEventListener('open', onOpen);
                    this.ws.removeEventListener('error', onError);
                    reject(new Error('WebSocket connection failed'));
                };
                this.ws.addEventListener('open', onOpen);
                this.ws.addEventListener('error', onError);
            });
        }
        
        this.debug(`WebSocket ready to send, state: ${this.ws.readyState}`);
        await this.sendKexInit();
        
        return new Promise((resolve) => {
            this._onHandshakeComplete = resolve;
        });
    }

    async handleBannerData(data) {
        this.readBuffer = this.concatUint8(this.readBuffer, data);
        
        const text = new TextDecoder().decode(this.readBuffer);
        const idx = text.indexOf('\r\n');
        
        if (idx !== -1) {
            const banner = text.substring(0, idx);
            this.serverVersion = banner;
            this.debug(`Server banner: ${banner}`);
            
            this.sendKexInitAfterBanner();
            
            this.readBuffer = this.readBuffer.slice(idx + 2);
            this.state = 'keyinit';
            
            this.debug(`Banner processed, state now keyinit, remaining bytes: ${this.readBuffer.length}`);
            
            if (this.readBuffer.length > 0) {
                const remaining = this.readBuffer;
                this.readBuffer = new Uint8Array(0);
                this.debug(`Calling handleData with remaining ${remaining.length} bytes`);
                await this.handleData(remaining);
            } else {
                this.debug('Waiting for server KEXINIT...');
            }
        }
    }

    async sendKexInit() {
        this.debug('Sending banner...');
        this.debug(`WebSocket readyState: ${this.ws.readyState}`);
        
        if (this.ws.readyState !== WebSocket.OPEN) {
            throw new Error(`WebSocket not open (state: ${this.ws.readyState})`);
        }
        
        const banner = 'SSH-2.0-OpenSSH_8.9p1 WebSSH\r\n';
        const encoder = new TextEncoder();
        this.ws.send(encoder.encode(banner));
        this.debug('Banner sent, waiting for server banner...');
    }

    async sendKexInitAfterBanner() {
        this.debug('Sending KEXINIT...');
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_KEXINIT);
        buf.append(getRandomBytes(16));
        
        buf.appendString('diffie-hellman-group14-sha256');
        buf.appendString('ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-256,rsa-sha2-512');
        
        buf.appendString('aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com');
        buf.appendString('aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com');
        
        buf.appendString('hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com');
        buf.appendString('hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com');
        
        buf.appendString('none');
        buf.appendString('none');
        
        buf.appendString('');
        buf.appendString('');
        buf.appendByte(0);
        buf.appendInt32(0);
        
        this.kex = {
            payload: buf.toUint8Array(),
            cookie: buf.toUint8Array().slice(1, 17),
            kexAlgos: ['diffie-hellman-group14-sha256'],
            serverHostKeyAlgos: ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-ed25519', 'ecdsa-sha2-nistp256'],
            encAlgosClientServer: ['aes256-ctr', 'aes192-ctr', 'aes128-ctr'],
            encAlgosServerClient: ['aes256-ctr', 'aes192-ctr', 'aes128-ctr'],
            macAlgosClientServer: ['hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'],
            macAlgosServerClient: ['hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'],
            compAlgosClientServer: ['none'],
            compAlgosServerClient: ['none'],
            languagesClientServer: [''],
            languagesServerClient: [''],
            firstKexPacketFollows: false,
            reserved: 0
        };
        
        this.debug('Sending KEXINIT packet...');
        this.sendPacket(buf.toUint8Array());
        this.debug('KEXINIT sent');
    }

    async handleData(data) {
        try {
            if (this.state === 'banner') {
                await this.handleBannerData(data);
                return;
            }
            
            this.readBuffer = this.concatUint8(this.readBuffer, data);
            
            this.debug(`handleData: state=${this.state}, buffer=${this.readBuffer.length}`);
            
            while (true) {
                if (this.state === 'transport' && this.incomingCipher) {
                    if (!await this.decryptNextPacket()) break;
                } else if (this.state === 'keyinit') {
                    if (!await this.readRawPacket()) break;
                } else {
                    if (!await this.readRawPacket()) break;
                }
            }
        } catch (e) {
            this.debug('handleData error: ' + e.message);
            console.error('handleData error:', e);
        }
    }

    concatUint8(...arrays) {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of arrays) {
            result.set(arr, offset);
            offset += arr.length;
        }
        return result;
    }

    async readRawPacket() {
        this.debug(`readRawPacket: buffer has ${this.readBuffer.length} bytes`);
        
        if (this.readBuffer.length < 4) {
            return false;
        }
        
        const len = (this.readBuffer[0] << 24) | (this.readBuffer[1] << 16) | 
                    (this.readBuffer[2] << 8) | this.readBuffer[3];
        
        this.debug(`readRawPacket: len field = ${len} (0x${len.toString(16)}), first 16 bytes: ${Array.from(this.readBuffer.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);
        
        if (len > 100000 || len < 0) {
            this.debug('Invalid length, clearing buffer and waiting for more data');
            this.readBuffer = new Uint8Array(0);
            return false;
        }
        
        const packetLen = 4 + len;
        if (this.readBuffer.length < packetLen) {
            this.debug(`readRawPacket: need ${packetLen}, have ${this.readBuffer.length}`);
            return false;
        }
        
        const packet = this.readBuffer.slice(0, packetLen);
        this.readBuffer = this.readBuffer.slice(packetLen);
        
        const paddingLength = packet[4];
        const payloadLength = len - paddingLength - 1;
        const payload = packet.slice(5, 5 + payloadLength);
        
        console.log('About to call handlePacket with', payload.length, 'bytes (payload only)');
        await this.handlePacket(payload, packet);
        this.incomingSeq++;
        return true;
    }

    async decryptNextPacket() {
        if (!this.incomingCipher) {
            return this.readRawPacket();
        }
        
        const blockSize = 16;
        
        if (this.readBuffer.length < blockSize) return false;
        
        const savedState = this.incomingCipher.saveState();
        
        const firstBlock = await this.incomingCipher.decrypt(this.readBuffer.slice(0, blockSize));
        
        const len = (firstBlock[0] << 24) | (firstBlock[1] << 16) | 
                    (firstBlock[2] << 8) | firstBlock[3];
        
        this.debug(`decryptNextPacket: len=${len}, buffer=${this.readBuffer.length}`);
        
        if (len > 100000 || len < 0) {
            this.debug('Invalid decrypted length');
            this.incomingCipher.restoreState(savedState);
            return false;
        }
        
        const packetLen = 4 + len;
        const macLen = 32;
        
        if (this.readBuffer.length < packetLen + macLen) {
            this.incomingCipher.restoreState(savedState);
            return false;
        }
        
        this.incomingCipher.restoreState(savedState);
        
        const encrypted = this.readBuffer.slice(0, packetLen);
        const mac = this.readBuffer.slice(packetLen, packetLen + macLen);
        
        const decrypted = await this.incomingCipher.decrypt(encrypted);
        
        const expectedMac = await this.computeIncomingMac(this.incomingSeq, decrypted);
        if (expectedMac && arrayToHex(expectedMac) !== arrayToHex(mac)) {
            this.debug('MAC check failed');
            this.debug(`Expected: ${arrayToHex(expectedMac)}`);
            this.debug(`Got: ${arrayToHex(mac)}`);
            return false;
        }
        
        this.readBuffer = this.readBuffer.slice(packetLen + macLen);
        
        const paddingLength = decrypted[4];
        const payloadLength = len - paddingLength - 1;
        const payload = decrypted.slice(5, 5 + payloadLength);
        
        await this.handlePacket(payload, decrypted);
        this.incomingSeq++;
        return true;
    }

    async computeIncomingMac(seq, data) {
        if (!this.incomingMac) return null;
        
        const buf = new SSHBuffer();
        buf.appendInt32(seq);
        buf.append(data);
        
        return await computeHMACSHA256(this.incomingMac.key, buf.toUint8Array());
    }

    async computeOutgoingMac(seq, data) {
        if (!this.outgoingMac) return null;
        
        const buf = new SSHBuffer();
        buf.appendInt32(seq);
        buf.append(data);
        
        return await computeHMACSHA256(this.outgoingMac.key, buf.toUint8Array());
    }

    async handlePacket(payload, fullPacket) {
        const pkt = SSHPacket.from(payload);
        const msgType = pkt.readByte();
        
        this.debug(`handlePacket: msgType=${msgType}, state=${this.state}`);
        
        switch (msgType) {
            case SSH_MSG_KEXINIT:
                this.handleKexInit(pkt, payload);
                break;
            case SSH_MSG_NEWKEYS:
                this.handleNewKeys();
                break;
            case SSH_MSG_KEXDH_REPLY:
                await this.handleKexDHReply(pkt);
                break;
            case SSH_MSG_SERVICE_ACCEPT:
                this.handleServiceAccept(pkt);
                break;
            case SSH_MSG_USERAUTH_SUCCESS:
                this.handleAuthSuccess();
                break;
            case SSH_MSG_USERAUTH_FAILURE:
                this.handleAuthFailure(pkt);
                break;
            case SSH_MSG_USERAUTH_BANNER:
                this.handleAuthBanner(pkt);
                break;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                this.handleChannelOpenConfirmation(pkt);
                break;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                this.handleChannelOpenFailure(pkt);
                break;
            case SSH_MSG_CHANNEL_DATA:
                this.handleChannelData(pkt);
                break;
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                this.handleChannelExtendedData(pkt);
                break;
            case SSH_MSG_CHANNEL_CLOSE:
                this.handleChannelClose(pkt);
                break;
            case SSH_MSG_CHANNEL_EOF:
                this.handleChannelEof(pkt);
                break;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                break;
            case SSH_MSG_CHANNEL_SUCCESS:
                this.debug('Channel request succeeded');
                break;
            case SSH_MSG_CHANNEL_FAILURE:
                this.debug('Channel request failed');
                break;
            case SSH_MSG_GLOBAL_REQUEST:
                this.handleGlobalRequest(pkt);
                break;
            case SSH_MSG_DISCONNECT:
                this.debug('Server disconnected');
                if (this.onClose) this.onClose();
                break;
            default:
                this.debug(`Unhandled message type: ${msgType}`);
        }
    }

    handleKexInit(pkt, payload) {
        pkt.offset = 0;
        pkt.readByte();
        
        const cookie = pkt.buffer.slice(pkt.offset, pkt.offset + 16);
        pkt.offset += 16;
        
        this.serverKex = {
            payload: payload,
            cookie: cookie,
            kexAlgos: pkt.readStringText().split(','),
            serverHostKeyAlgos: pkt.readStringText().split(','),
            encAlgosClientServer: pkt.readStringText().split(','),
            encAlgosServerClient: pkt.readStringText().split(','),
            macAlgosClientServer: pkt.readStringText().split(','),
            macAlgosServerClient: pkt.readStringText().split(','),
            compAlgosClientServer: pkt.readStringText().split(','),
            compAlgosServerClient: pkt.readStringText().split(','),
            languagesClientServer: pkt.readStringText().split(','),
            languagesServerClient: pkt.readStringText().split(','),
            firstKexPacketFollows: pkt.readBoolean(),
            reserved: pkt.readByte()
        };
        
        this.debug('Received server KEXINIT, starting key exchange...');
        this.debug(`Server kex algos: ${this.serverKex.kexAlgos.join(', ')}`);
        this.debug(`Server enc algos C->S: ${this.serverKex.encAlgosClientServer.join(', ')}`);
        this.debug(`Server mac algos C->S: ${this.serverKex.macAlgosClientServer.join(', ')}`);
        
        this.startKeyExchange().catch(e => {
            this.debug(`Key exchange error: ${e.message}`);
            console.error('Key exchange error:', e);
        });
    }

    async startKeyExchange() {
        this.debug('Starting DH key exchange...');
        const e = bytesToBigInt(getRandomBytes(256));
        const n = bytesToBigInt(MODULUS_P);
        const g = 2n;
        
        const clientPublic = modPow(g, e, n);
        const eBytes = bigIntToMpint(clientPublic);
        
        this.dhE = e;
        this.dhF = clientPublic;
        this.dhEBytes = eBytes;
        
        this.debug(`DH public key generated (${clientPublic.toString().length} digits)`);
        
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_KEXDH_INIT);
        buf.appendBuffer(eBytes);
        
        this.debug(`KEXDH_INIT: e length = ${eBytes.length} bytes`);
        
        const packet = buf.toUint8Array();
        this.debug(`Sending KEXDH_INIT packet (${packet.length} bytes)`);
        this.sendPacket(packet);
        this.debug('KEXDH_INIT sent, waiting for KEXDH_REPLY...');
    }

    async handleKexDHReply(pkt) {
        const serverHostKey = pkt.readString();
        const fBytes = pkt.readString();
        const f = bytesToBigInt(fBytes);
        const signature = pkt.readString();
        
        this.debug(`Received KEXDH_REPLY: f length = ${fBytes.length} bytes`);
        
        const n = bytesToBigInt(MODULUS_P);
        const sharedSecret = modPow(f, this.dhE, n);
        
        const k = bigIntToMpint(sharedSecret);
        
        this.debug(`Shared secret K length = ${k.length} bytes`);
        
        const hData = new SSHBuffer();
        hData.appendString('SSH-2.0-OpenSSH_8.9p1 WebSSH');
        hData.appendString(this.serverVersion || 'SSH-2.0-OpenSSH_8.4p1');
        hData.appendBuffer(this.kex.payload);
        hData.appendBuffer(this.serverKex.payload);
        hData.appendBuffer(serverHostKey);
        hData.appendBuffer(this.dhEBytes);
        hData.appendBuffer(fBytes);
        hData.appendBuffer(k);
        
        const exchangeHash = await computeSHA256(hData.toUint8Array());
        
        if (!this.sessionId) {
            this.sessionId = exchangeHash;
        }
        
        this.debug(`Exchange hash computed (${exchangeHash.length} bytes)`);
        
        await this.deriveKeys(k, exchangeHash);
        
        this.sendPacket(new Uint8Array([SSH_MSG_NEWKEYS]));
        this.debug('Sent NEWKEYS');
    }

    async deriveKeys(k, h) {
        const sessionId = this.sessionId || h;
        
        const kBuf = new SSHBuffer();
        kBuf.appendBuffer(k);
        const kString = kBuf.toUint8Array();
        
        this.debug(`Deriving keys: K=${k.length} bytes (string: ${kString.length}), H=${h.length} bytes, session_id=${sessionId.length} bytes`);
        
        const ivClientToServer = await computeSHA256(this.concatUint8(kString, h, new Uint8Array([0x41]), sessionId));
        const ivServerToClient = await computeSHA256(this.concatUint8(kString, h, new Uint8Array([0x42]), sessionId));
        
        const encKeyClientToServer = await computeSHA256(this.concatUint8(kString, h, new Uint8Array([0x43]), sessionId));
        const encKeyServerToClient = await computeSHA256(this.concatUint8(kString, h, new Uint8Array([0x44]), sessionId));
        
        const macKeyClientToServer = await computeSHA256(this.concatUint8(kString, h, new Uint8Array([0x45]), sessionId));
        const macKeyServerToClient = await computeSHA256(this.concatUint8(kString, h, new Uint8Array([0x46]), sessionId));
        
        this.debug(`IV C->S: ${Array.from(ivClientToServer.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        this.debug(`IV S->C: ${Array.from(ivServerToClient.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        this.debug(`Enc C->S: ${Array.from(encKeyClientToServer.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        this.debug(`Enc S->C: ${Array.from(encKeyServerToClient.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}`);
        
        this.incomingCipher = new AESCounter(encKeyServerToClient, ivServerToClient);
        await this.incomingCipher.init();
        
        this.outgoingCipher = new AESCounter(encKeyClientToServer, ivClientToServer);
        await this.outgoingCipher.init();
        
        this.incomingMac = { key: macKeyServerToClient };
        this.outgoingMac = { key: macKeyClientToServer };
        
        this.debug('Keys derived and ciphers initialized');
    }

    handleNewKeys() {
        this.debug('Received NEWKEYS, switching to transport layer');
        this.state = 'transport';
        
        this.debug('Resolving handshake promise');
        if (this._onHandshakeComplete) {
            this._onHandshakeComplete();
            this._onHandshakeComplete = null;
        }
    }

    async requestService(service) {
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_SERVICE_REQUEST);
        buf.appendString(service);
        this.sendPacket(buf.toUint8Array());
    }

    handleServiceAccept(pkt) {
        const service = pkt.readStringText();
        this.debug(`Service ${service} accepted`);
        
        if (service === SSH_SERVICE_USERAUTH) {
            this.serviceAccepted = true;
        } else if (service === SSH_SERVICE_CONNECTION) {
            this.debug('Connection service ready');
        }
    }

    async authenticate(username = 'root', password = 'password') {
        this.debug(`Requesting userauth service...`);
        this.requestService(SSH_SERVICE_USERAUTH);
        
        await new Promise((resolve) => {
            const check = setInterval(() => {
                if (this.serviceAccepted) {
                    clearInterval(check);
                    resolve();
                }
            }, 50);
        });
        
        this.debug(`Authenticating as ${username}...`);
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_USERAUTH_REQUEST);
        buf.appendString(username);
        buf.appendString(SSH_SERVICE_CONNECTION);
        buf.appendString(SSH_AUTH_TYPE_PASSWORD);
        buf.appendByte(0);
        buf.appendString(password);
        
        this.sendPacket(buf.toUint8Array());
        
        await new Promise((resolve, reject) => {
            const check = setInterval(() => {
                if (this.authenticated) {
                    clearInterval(check);
                    resolve();
                } else if (this.authFailed) {
                    clearInterval(check);
                    reject(new Error('Authentication failed'));
                }
            }, 50);
        });
    }

    handleAuthSuccess() {
        this.debug('Authentication successful!');
        this.authenticated = true;
    }

    handleAuthFailure(pkt) {
        const auths = pkt.readStringText().split(',');
        this.debug(`Authentication failed. Available methods: ${auths}`);
        this.authFailed = true;
    }

    handleAuthBanner(pkt) {
        const banner = pkt.readStringText();
        this.debug(`Banner: ${banner}`);
    }

    handleGlobalRequest(pkt) {
        const requestName = pkt.readStringText();
        const wantReply = pkt.readBoolean();
        this.debug(`Global request: ${requestName}, wantReply: ${wantReply}`);
        
        if (wantReply) {
            const buf = new SSHBuffer();
            buf.appendByte(SSH_MSG_REQUEST_FAILURE);
            this.sendPacket(buf.toUint8Array());
        }
    }

    async openShell(rows = 24, cols = 80) {
        const localChannelId = ++this.localChannelId;
        
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_CHANNEL_OPEN);
        buf.appendString(SSH_CHANNEL_TYPE_SESSION);
        buf.appendInt32(localChannelId);
        buf.appendInt32(0x7fffffff);
        buf.appendInt32(0x40000);
        
        await this.sendPacket(buf.toUint8Array());
        
        this.channels.set(localChannelId, { type: 'session', pending: true });
        this.shellChannel = localChannelId;
        
        return new Promise((resolve) => {
            const checkOpen = setInterval(async () => {
                const ch = this.channels.get(localChannelId);
                if (ch && !ch.pending) {
                    clearInterval(checkOpen);
                    await this.requestPty(rows, cols, localChannelId);
                    await this.requestShell(localChannelId);
                    resolve(localChannelId);
                }
            }, 100);
        });
    }

    async requestPty(rows, cols, localChannelId) {
        const ch = this.channels.get(localChannelId);
        if (!ch) return;
        
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_CHANNEL_REQUEST);
        buf.appendInt32(ch.remoteId);
        buf.appendString('pty-req');
        buf.appendByte(0);
        buf.appendString('xterm-256color');
        buf.appendInt32(cols);
        buf.appendInt32(rows);
        buf.appendInt32(0);
        buf.appendInt32(0);
        buf.appendString('');
        
        await this.sendPacket(buf.toUint8Array());
    }

    async requestShell(localChannelId) {
        const ch = this.channels.get(localChannelId);
        if (!ch) return;
        
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_CHANNEL_REQUEST);
        buf.appendInt32(ch.remoteId);
        buf.appendString('shell');
        buf.appendByte(1);
        
        await this.sendPacket(buf.toUint8Array());
    }

    handleChannelOpenConfirmation(pkt) {
        const recipientChannel = pkt.readUint32();
        const senderChannel = pkt.readUint32();
        
        this.debug(`Channel ${recipientChannel} opened (remote: ${senderChannel})`);
        
        const ch = this.channels.get(recipientChannel);
        if (ch) {
            ch.pending = false;
            ch.remoteId = senderChannel;
        }
    }

    handleChannelOpenFailure(pkt) {
        const remoteChannelId = pkt.readUint32();
        const reasonCode = pkt.readUint32();
        this.debug(`Channel open failed: ${reasonCode}`);
        this.close();
    }

    handleChannelData(pkt) {
        const recipientChannel = pkt.readUint32();
        const data = pkt.readString();
        
        const text = new TextDecoder().decode(data);
        this.debug(`Channel data: recipientChannel=${recipientChannel}, shellChannel=${this.shellChannel}, data=${text.length} chars`);
        
        if (this.onData && recipientChannel === this.shellChannel) {
            this.onData(text);
        }
    }

    handleChannelClose(pkt) {
        const recipientChannel = pkt.readUint32();
        const ch = this.channels.get(recipientChannel);
        if (ch) {
            ch.closed = true;
            this.debug(`Channel ${recipientChannel} closed`);
        }
    }

    handleChannelEof(pkt) {
        const remoteChannelId = pkt.readUint32();
        if (this.onData) {
            this.onData('');
        }
    }

    async sendPacket(payload) {
        if (this.state === 'transport' && this.outgoingCipher) {
            const blockSize = 16;
            
            let paddingLen = blockSize - ((payload.length + 1 + 4) % blockSize);
            if (paddingLen < 4) paddingLen += blockSize;
            
            const packetLen = 1 + payload.length + paddingLen;
            
            const buf = new SSHBuffer();
            buf.appendInt32(packetLen);
            buf.appendByte(paddingLen);
            buf.append(payload);
            buf.append(getRandomBytes(paddingLen));
            
            const plaintext = buf.toUint8Array();
            this.debug(`sendPacket encrypted: plaintext ${plaintext.length} bytes`);
            this.debug(`Plaintext: ${Array.from(plaintext.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' ')}...`);
            
            const encrypted = await this.outgoingCipher.encrypt(plaintext);
            this.debug(`Encrypted: ${Array.from(encrypted.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' ')}...`);
            
            const mac = await this.computeOutgoingMac(this.outgoingSeq, plaintext);
            this.debug(`MAC (seq=${this.outgoingSeq}): ${mac ? Array.from(mac.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ') : 'none'}`);
            
            const result = new SSHBuffer();
            result.append(encrypted);
            if (mac) result.append(mac);
            
            const packet = result.toUint8Array();
            this.debug(`Sending encrypted packet: ${packet.length} bytes (enc=${encrypted.length}, mac=${mac ? mac.length : 0})`);
            this.ws.send(packet);
            this.outgoingSeq++;
        } else {
            const blockSize = 8;
            
            let paddingLen = blockSize - ((payload.length + 1 + 4) % blockSize);
            if (paddingLen < 4) paddingLen += blockSize;
            
            const packetLen = 1 + payload.length + paddingLen;
            
            this.debug(`sendPacket: payload=${payload.length}, padding=${paddingLen}, total=${packetLen + 4}`);
            
            const buf = new SSHBuffer();
            buf.appendInt32(packetLen);
            buf.appendByte(paddingLen);
            buf.append(payload);
            buf.append(getRandomBytes(paddingLen));
            
            const packet = buf.toUint8Array();
            this.debug(`Sending packet: ${Array.from(packet.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(' ')}...`);
            
            this.ws.send(packet);
            this.outgoingSeq++;
        }
    }

    sendData(data) {
        if (!this.shellChannel) return;
        
        const ch = this.channels.get(this.shellChannel);
        if (!ch || ch.closed) return;
        
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_CHANNEL_DATA);
        buf.appendInt32(ch.remoteId);
        
        if (typeof data === 'string') {
            buf.appendBuffer(new TextEncoder().encode(data));
        } else {
            buf.appendBuffer(data);
        }
        
        this.sendPacket(buf.toUint8Array());
    }

    resize(rows, cols) {
        if (!this.shellChannel) return;
        
        const ch = this.channels.get(this.shellChannel);
        if (!ch || ch.closed) return;
        
        const buf = new SSHBuffer();
        buf.appendByte(SSH_MSG_CHANNEL_REQUEST);
        buf.appendInt32(ch.remoteId);
        buf.appendString('window-change');
        buf.appendByte(0);
        buf.appendInt32(cols);
        buf.appendInt32(rows);
        buf.appendInt32(0);
        buf.appendInt32(0);
        
        this.sendPacket(buf.toUint8Array());
    }

    close() {
        if (this.shellChannel) {
            const ch = this.channels.get(this.shellChannel);
            if (ch && !ch.closed) {
                const buf = new SSHBuffer();
                buf.appendByte(SSH_MSG_CHANNEL_CLOSE);
                buf.appendInt32(ch.remoteId);
                this.sendPacket(buf.toUint8Array());
            }
        }
        
        this.ws.close();
    }
}

window.SSHConnection = SSHConnection;
