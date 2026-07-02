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

For a quick all-in-one local development setup:

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

For real multi-machine setup, public-key exchange, and forward testing with the
demi client, see [docs/SETUP_AND_FORWARD_TEST.md](docs/SETUP_AND_FORWARD_TEST.md).

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
