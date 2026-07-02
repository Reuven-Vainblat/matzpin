# Real Setup And Local Forward Test

This project has three runtime pieces:

```text
server -> Raspberry Pi daemon -> downstream client/service
```

The server sends one encrypted signed message to the Pi over mutual TLS. The Pi
decrypts and validates the message, then forwards the plaintext to a downstream
TLS service. For a simple test, use `encryptor_demi_client` as that downstream
service on the Pi machine.

## Generate Separate Runtime Material

Generate the authority once:

```powershell
python tools/generate_dev_security.py --component authority --out authority-dev
```

Generate Pi runtime material:

```powershell
python tools/generate_dev_security.py `
  --component pi `
  --out pi-runtime `
  --authority-root authority-dev
```

Send this public key to the server:

```text
pi-runtime/exchange/pi_x25519.pub
```

Generate server runtime material:

```powershell
python tools/generate_dev_security.py `
  --component server `
  --out server-runtime `
  --authority-root authority-dev `
  --pi-public-key pi-runtime/exchange/pi_x25519.pub
```

Send this public key to the Pi:

```text
server-runtime/exchange/server_k1.pem
```

Trust the server signing public key on the Pi:

```powershell
python tools/generate_dev_security.py `
  --component trust-server `
  --out pi-runtime `
  --server-public-key server-runtime/exchange/server_k1.pem
```

## Run A Simple Local Downstream Client On The Pi

Check `pi-runtime/config/pi.local.json` for:

```json
"forward_host": "127.0.0.1",
"forward_port": 19443
```

Run the demi client on that host and port:

```powershell
$env:DEMI_CLIENT_HOST="127.0.0.1"
$env:DEMI_CLIENT_PORT="19443"
$env:DEMI_CLIENT_TLS_CERT="pi-runtime/pi/certs/pi.crt"
$env:DEMI_CLIENT_TLS_KEY="pi-runtime/pi/certs/pi.key"
$env:DEMI_CLIENT_RESPONSE="OK from demi client"
$env:DEMI_CLIENT_RECEIVED_OUTPUT="received-from-pi.txt"
python -m encryptor_demi_client.main
```

The demi client handles one forwarded message, writes the received plaintext to
`received-from-pi.txt`, sends the configured response back to the Pi, and exits.

## Run The Pi Daemon

In another terminal on the Pi machine:

```powershell
$env:ENCRYPTOR_PI_CONFIG="pi-runtime/config/pi.local.json"
python -m encryptor_pi.main
```

The Pi daemon keeps running and waits for the server connection.

## Run The Server

Before running the server, edit `server-runtime/config/server.local.json` so
`pi_host` points to the real Pi IP address or DNS name:

```json
"pi_host": "<PI_IP_OR_DNS>",
"pi_port": 18443
```

Then run:

```powershell
python -m encryptor_server.main "hello from real server" --config server-runtime/config/server.local.json
```

Expected server output:

```text
OK from demi client
```

On the Pi machine, `received-from-pi.txt` should contain:

```text
hello from real server
```

## Ports To Open

- The server must be able to reach the Pi on `pi_port`.
- The Pi must be able to reach the downstream client on `forward_host:forward_port`.
- For the simple local test, the downstream client is on the same Pi machine, so
  `forward_host` can stay `127.0.0.1`.

