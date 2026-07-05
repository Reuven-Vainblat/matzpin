# Encryptor Project Skeleton

This branch is a student skeleton for the Raspberry Pi/server encrypted
messaging project.

Target flow:

```text
server -> mutual TLS -> Raspberry Pi daemon -> decrypt/validate -> forward plaintext
```

The implementation is intentionally incomplete. The packages, command-line
entry points, dataclasses, and main function names are present so students can
fill in the behavior.

## Runtime Pieces

- `encryptor_server`: builds, encrypts, signs, and sends one message.
- `encryptor_pi`: receives, validates, decrypts, replay-checks, and forwards.
- `encryptor_demi_client`: simple downstream TLS service for local testing.
- `encryptor_common`: shared framing, protocol, and errors.
- `tools/generate_dev_security.py`: development key/certificate/config helper.

## Expected Student Work

Implement the TODOs in the skeleton:

- length-prefixed socket framing
- JSON envelope serialization
- mutual TLS client/server setup
- X25519, HKDF, AES-GCM, and Ed25519 message protection
- replay database checks
- downstream forwarding
- development key/certificate/config generation
- system tests for success and rejection cases

## Run Commands

After implementing the project, the intended commands are:

```powershell
python tools/generate_dev_security.py --out dev_runtime
python -m encryptor_demi_client.main --config dev_runtime/config/client.local.json
$env:ENCRYPTOR_PI_CONFIG="dev_runtime/config/pi.local.json"
python -m encryptor_pi.main
python -m encryptor_server.main "hello" --config dev_runtime/config/server.local.json
```
