# Encryptor Project

Cyber-oriented Raspberry Pi/server messaging project.

The Raspberry Pi runs a daemon that receives encrypted signed envelopes over
mutual TLS. The server creates those envelopes, using X25519 key agreement,
HKDF-SHA256, AES-256-GCM, and Ed25519 signatures.

```text
server -> mTLS -> Raspberry Pi daemon -> decrypt/validate -> forward plaintext
```

## Project Structure

```text
encryptor_daemon/
  pyproject.toml
  README.md
  encryptor_common/
    errors.py
    framing.py
    protocol.py
  encryptor_pi/
    main.py
    config.py
    tls_server.py
    processor.py
    crypto.py
    replay_db.py
    forwarder.py
    validator.py
  encryptor_server/
    main.py
    config.py
    tls_client.py
    crypto.py
  tools/
    generate_dev_security.py
```

## Generate Development Security Files

```powershell
cd encryptor_daemon
python tools/generate_dev_security.py --out .
```

By default this also writes local config files:

```text
config/pi.local.json
config/server.local.json
config/client.local.json
```

Environment-variable defaults are also supported:

```powershell
$env:SECURITY_OUT="."
$env:SECURITY_SENDER_ID="server"
$env:SECURITY_KEY_ID="k1"
$env:SECURITY_PI_HOSTNAME="raspberry-pi"
$env:SECURITY_SERVER_HOSTNAME="server"
python tools/generate_dev_security.py
```

For separate machines, generate the authority once, then generate each side
independently and exchange only public keys:

```powershell
python tools/generate_dev_security.py --component authority --out authority-dev

python tools/generate_dev_security.py --component pi `
  --out pi-runtime `
  --authority-root authority-dev

python tools/generate_dev_security.py --component server `
  --out server-runtime `
  --authority-root authority-dev `
  --pi-public-key pi-runtime/exchange/pi_x25519.pub

python tools/generate_dev_security.py --component trust-server `
  --out pi-runtime `
  --server-public-key server-runtime/exchange/server_k1.pem
```

The `exchange/` files are public key material:

- `pi-runtime/exchange/pi_x25519.pub`: copied to the server so it can encrypt messages to the Pi.
- `server-runtime/exchange/server_k1.pem`: copied to the Pi so it can verify server message signatures.

This creates separated runtime folders:

```text
authority/
  ca.key
pi/
  certs/ca.crt
  certs/pi.crt
  certs/pi.key
  keys/private/pi_x25519.pem
  keys/senders/server_k1.pem
server/
  certs/ca.crt
  keys/private/server_tls.crt
  keys/private/server_tls.key
  keys/private/server_k1.pem
  keys/public/pi_x25519.pub
```

There are no duplicate private keys here:

- `pi/certs/pi.key`: Pi TLS private key.
- `server/keys/private/server_tls.key`: server TLS private key for mutual TLS.
- `server/keys/private/server_k1.pem`: server Ed25519 signing private key.
- `pi/keys/private/pi_x25519.pem`: Pi X25519 private key for message decryption.
- `pi/keys/senders/server_k1.pem`: server Ed25519 public key copied to the Pi.
- `server/keys/public/pi_x25519.pub`: Pi X25519 public key copied to the server.

`authority/ca.key` is only for issuing development certificates. Keep it off
both runtime systems in real deployments.

## Run On The Raspberry Pi

Install the package on the Pi and run:

```powershell
python -m encryptor_pi.main
```

Or after installing the console script:

```powershell
encryptor-pi
```

Pi environment variables:

```powershell
$env:PI_HOST="0.0.0.0"
$env:PI_PORT="8443"
$env:PI_CA_CERT="pi/certs/ca.crt"
$env:PI_TLS_CERT="pi/certs/pi.crt"
$env:PI_TLS_KEY="pi/certs/pi.key"
$env:PI_RECIPIENT_ID="raspberry-pi"
$env:PI_SENDER_PUBLIC_KEYS_DIR="pi/keys/senders"
$env:PI_X25519_PRIVATE_KEY="pi/keys/private/pi_x25519.pem"
$env:PI_REPLAY_DB="pi/replay.sqlite3"
$env:PI_FORWARD_HOST="127.0.0.1"
$env:PI_FORWARD_PORT="9443"
```

## Run On The Server

The server creates an encrypted signed envelope and sends it to the Pi:

```powershell
python -m encryptor_server.main "hello from server"
```

Or after installing the console script:

```powershell
encryptor-server "hello from server"
```

Server environment variables:

```powershell
$env:SERVER_PI_HOST="127.0.0.1"
$env:SERVER_PI_PORT="8443"
$env:SERVER_CA_CERT="server/certs/ca.crt"
$env:SERVER_TLS_CERT="server/keys/private/server_tls.crt"
$env:SERVER_TLS_KEY="server/keys/private/server_tls.key"
$env:SERVER_SENDER_ID="server"
$env:SERVER_RECIPIENT_ID="raspberry-pi"
$env:SERVER_KEY_ID="k1"
$env:SERVER_SIGNING_PRIVATE_KEY="server/keys/private/server_k1.pem"
$env:SERVER_PI_X25519_PUBLIC_KEY="server/keys/public/pi_x25519.pub"
```

## Crypto Flow

The server:

1. Generates a fresh ephemeral X25519 keypair per message.
2. Derives a shared secret with the Pi X25519 public key.
3. Runs HKDF-SHA256 to derive an AES-256-GCM key.
4. Encrypts the plaintext with AES-GCM.
5. Signs the canonical envelope with Ed25519.
6. Sends the framed envelope over mutual TLS.

The Pi:

1. Checks metadata, freshness, and replay status.
2. Verifies the Ed25519 signature with `pi/keys/senders/server_k1.pem`.
3. Derives the same AES key using its X25519 private key and the server ephemeral public key.
4. Decrypts and authenticates the ciphertext.
5. Forwards plaintext over TLS to the downstream service.
6. Marks the message id as seen only after forwarding succeeds.

Envelope shape:

```json
{
  "version": 1,
  "message_id": "unique-message-id",
  "timestamp": "2026-06-30T12:00:00Z",
  "sender_id": "server",
  "recipient_id": "raspberry-pi",
  "key_id": "k1",
  "ephemeral_public_key": "base64url-raw-x25519-public-key",
  "nonce": "base64url-12-byte-nonce",
  "ciphertext": "base64url-ciphertext-plus-gcm-tag",
  "signature": "base64url-ed25519-signature",
  "aad": {}
}
```

## Certificate SANs

The development certificates include both DNS names and `127.0.0.1` because
modern TLS validates Subject Alternative Names. Use DNS SANs when connecting by
hostname, and IP SANs when connecting by numeric IP address.
