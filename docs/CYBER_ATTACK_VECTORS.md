# Cyber Attack Vectors

This document maps likely attack vectors against the current secure-forwarding
project:

```text
server -> mutual TLS -> Pi daemon -> decrypt/validate -> downstream client
```

It is written as a defensive checklist for testing, monitoring, and hardening.

## Denial Of Service

### TCP Connection Flood

An attacker can repeatedly open TCP connections to the Pi daemon port. Even if
mutual TLS later rejects the peer, the Pi still spends resources accepting the
connection and performing TLS work.

Impact:
- high CPU from TLS handshakes
- exhausted socket backlog
- real server messages delayed or dropped

Mitigations:
- firewall allowlist trusted server IPs where possible
- rate-limit inbound connections
- run behind a VPN/private network
- add connection metrics and alerts

### Slow Client / Slowloris

A client can connect and send the TLS or framed-message bytes very slowly. The
current daemon has request timeouts, but because the Pi server is still
synchronous, one slow connection can occupy the only processing loop until it
times out.

Impact:
- one slow peer can delay legitimate messages
- repeated slow connections can keep the daemon busy

Mitigations:
- keep short request timeouts
- move to a threaded, async, or worker-pool server
- cap active connections per source IP

### Large Message Flood

The framing layer enforces a maximum message size, but an attacker can still
send many near-limit messages. Each message consumes network bandwidth, memory,
JSON parsing, signature verification, and possibly decryption work.

Impact:
- CPU and memory pressure
- logs fill quickly
- replay database growth if messages are valid and unique

Mitigations:
- keep `max_message_size` as small as the real use case allows
- rate-limit per sender/IP
- monitor rejected oversized frames
- avoid logging full payloads

### Downstream Blocking

After decrypting a message, the Pi synchronously forwards plaintext to the
downstream service. If that service is slow, unavailable, or intentionally
delays responses, the Pi waits and cannot process the next request.

Impact:
- valid messages can stall the whole pipeline
- attacker with valid credentials can cause repeated downstream timeouts

Mitigations:
- keep downstream timeout low
- isolate forwarding in a worker queue
- add retry/backoff policy
- monitor downstream latency and failures

### Replay Database Growth

Replay protection stores processed message IDs. A valid sender can generate many
unique message IDs and grow the SQLite database over time.

Impact:
- disk exhaustion
- slower replay checks
- operational cleanup required

Mitigations:
- schedule replay cleanup
- enforce maximum replay DB age/size
- monitor disk usage
- reject senders that exceed expected message rates

## Authentication And Trust

### Stolen Server TLS Key

If the server TLS private key is stolen, an attacker may pass mutual TLS as that
server. Message-level Ed25519 signing still protects the encrypted envelope only
if the signing key is not also stolen.

Mitigations:
- store TLS private keys outside source control
- restrict filesystem permissions
- rotate certificates after suspected compromise
- use separate TLS and signing keys, as the project already does

### Stolen Server Signing Key

If the Ed25519 signing private key is stolen, an attacker can create envelopes
that the Pi accepts as authentic, assuming they also have the Pi public X25519
key.

Impact:
- unauthorized commands/messages forwarded to downstream service
- replay protection does not help against fresh signed messages

Mitigations:
- protect `server/keys/private/server_k1.pem`
- support key rotation with new `key_id` values
- remove old public keys from the Pi trust directory
- monitor unusual sender rates and message IDs

### Stolen Pi X25519 Private Key

If the Pi X25519 private key is stolen, captured encrypted messages can be
decrypted because the Pi key is static.

Mitigations:
- protect `pi/keys/private/pi_x25519.pem`
- rotate the Pi X25519 key if compromised
- regenerate and redistribute the Pi public key to servers
- consider hardware-backed key storage for production

### CA Key Compromise

If `authority/ca.key` is stolen, an attacker can issue new TLS certificates that
both sides may trust.

Mitigations:
- keep the CA key offline after generating runtime material
- do not copy `authority/ca.key` to servers or the Pi
- rotate the CA and all leaf certificates after compromise

### Wrong Or Overbroad CA Trust

If the Pi or server trusts a CA that signs unrelated certificates, unexpected
clients may complete mutual TLS.

Mitigations:
- use a dedicated CA for this project
- keep certificate directories minimal
- add application-level sender checks, which the Ed25519 signature layer already
  partially provides

## Protocol Abuse

### Malformed Frame Or JSON

An attacker can send invalid frame lengths, invalid UTF-8, invalid JSON, missing
fields, or fields with unexpected types.

Impact:
- rejected requests
- noisy logs
- possible daemon crash if an unexpected exception path is not handled

Mitigations:
- keep per-connection exception handling around the Pi loop
- add stricter schema/type validation
- test malformed envelope cases

### Replay Attempts

An attacker can resend a previously valid envelope. The replay database should
reject message IDs that were already processed.

Residual risk:
- if the Pi forwards plaintext successfully but crashes before marking the
  message as seen, a retry may forward the same plaintext again

Mitigations:
- decide whether the system is at-least-once or exactly-once-ish
- mark in-progress messages before forwarding, or make downstream operations
  idempotent

### Timestamp Manipulation

Messages outside the allowed clock skew are rejected. Attackers may try stale or
future timestamps to bypass simple freshness checks.

Mitigations:
- keep clocks synchronized with NTP
- keep `max_clock_skew_seconds` small
- alert on repeated timestamp failures

## Network Position Attacks

### Man In The Middle

Mutual TLS and certificate validation protect against basic MITM attacks.
However, this depends on correct CA files, correct certificate SANs, and private
key secrecy.

Mitigations:
- verify generated certs contain the IP/DNS used in config
- avoid disabling hostname verification
- rotate certs when IPs or trust roots change

### Plain TCP Probing

Tools like `nc` can confirm the port is open, but they do not speak mutual TLS.
The Pi should log these as rejected connections.

Mitigations:
- treat these logs as expected during connectivity testing
- distinguish TCP reachability tests from full application flow tests

## Local Host And Deployment Misconfiguration

### Binding To Localhost

If the Pi config binds to `127.0.0.1`, only local processes can connect.
Remote servers need the Pi daemon to bind to `0.0.0.0` or a reachable interface
IP.

Mitigations:
- use the setup script with `-PiIp`
- verify with `netstat` or `Test-NetConnection`

### Wrong Source Address

The server should not bind its outgoing connection to `127.0.0.1` for real
remote communication.

Mitigations:
- generated real-machine configs set `local_host` to `null`
- only use `local_host` for localhost tests

### Cross-OS Path Problems

Runtime configs generated on Windows but executed on Linux must use portable
paths. Backslashes in JSON paths can cause Linux to look for the wrong filename.

Mitigations:
- generated configs use `/` separators
- run the setup script after pulling the latest code

## Logging And Monitoring

Useful events to monitor:
- Pi accepted TCP connection
- mutual TLS completed
- encrypted request received
- signature verified
- replay rejected
- payload decrypted
- downstream forwarding started/failed
- downstream response received
- server response received

Avoid logging:
- plaintext payload contents
- private key paths beyond operational debugging
- private key material
- full certificates unless explicitly troubleshooting

## Priority Hardening Checklist

1. Restrict inbound Pi port to trusted server IPs or VPN networks.
2. Add concurrency or a worker queue to prevent one connection blocking all
   traffic.
3. Add replay database cleanup and disk monitoring.
4. Add strict envelope schema validation.
5. Add key rotation procedures for TLS certs, signing keys, and Pi encryption
   keys.
6. Keep the CA key offline and out of runtime folders.
7. Add operational alerts for repeated TLS failures, replay attempts, and
   downstream timeouts.
