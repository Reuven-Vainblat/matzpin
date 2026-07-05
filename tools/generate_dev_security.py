"""Generate development certificates and message keys.

This creates local testing material for the encryptor daemon. Do not reuse
these files for production deployments.

The generated files support a classroom/dev environment:
TLS keys prove network identity, Ed25519 keys sign message envelopes, and
X25519 keys support per-message key agreement.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

MAX_MESSAGE_SIZE = 1_048_576


def main() -> None:
    """Parse configuration and generate development security material.

    All arguments also have environment-variable defaults, which makes the
    script easy to run from deployment notes, CI jobs, or classroom exercises.
    """

    parser = argparse.ArgumentParser(
        description="Generate development certificates and message keys.",
    )
    parser.add_argument("--out", default=_env("SECURITY_OUT", "."), help="Project/runtime directory to write into.")
    parser.add_argument(
        "--component",
        choices=("all", "authority", "pi", "server", "trust-server", "trust-pi"),
        default="all",
    )
    parser.add_argument("--authority-root", help="Directory containing authority/ca.key for pi/server components.")
    parser.add_argument("--server-public-key", help="Server Ed25519 public key to trust on the Pi.")
    parser.add_argument("--pi-public-key", help="Pi X25519 public key to encrypt to on the server.")
    parser.add_argument("--no-config", action="store_true", help="Do not write local JSON config files.")
    parser.add_argument("--pi-port", type=int, default=int(_env("SECURITY_PI_PORT", "18443")))
    parser.add_argument("--server-port", type=int, default=int(_env("SECURITY_SERVER_PORT", "0")))
    parser.add_argument("--client-port", type=int, default=int(_env("SECURITY_CLIENT_PORT", "19443")))
    parser.add_argument("--sender-id", default=_env("SECURITY_SENDER_ID", "server"))
    parser.add_argument("--key-id", default=_env("SECURITY_KEY_ID", "k1"))
    parser.add_argument("--pi-hostname", default=_env("SECURITY_PI_HOSTNAME", "raspberry-pi"))
    parser.add_argument("--server-hostname", default=_env("SECURITY_SERVER_HOSTNAME", "server"))
    parser.add_argument(
        "--pi-ip",
        action="append",
        default=_split_csv(_env("SECURITY_PI_IPS", "")),
        help="IP address to add to the Pi TLS certificate SAN. Can be repeated.",
    )
    parser.add_argument(
        "--server-ip",
        action="append",
        default=_split_csv(_env("SECURITY_SERVER_IPS", "")),
        help="IP address to add to the server TLS certificate SAN. Can be repeated.",
    )
    parser.add_argument(
        "--pi-listen-host",
        default=_env("SECURITY_PI_LISTEN_HOST", ""),
        help="Host/IP for the generated Pi config to bind. Defaults to 0.0.0.0 when --pi-ip is set, otherwise 127.0.0.1.",
    )
    parser.add_argument(
        "--pi-connect-host",
        default=_env("SECURITY_PI_CONNECT_HOST", ""),
        help="Host/IP for the generated server config to connect to. Defaults to the first --pi-ip, otherwise 127.0.0.1.",
    )
    args = parser.parse_args()

    root = Path(args.out)
    authority_root = Path(args.authority_root) if args.authority_root else root
    pi_ips = _unique_values(args.pi_ip)
    server_ips = _unique_values(args.server_ip)
    pi_listen_host = args.pi_listen_host or ("0.0.0.0" if pi_ips else "127.0.0.1")
    pi_connect_host = args.pi_connect_host or (pi_ips[0] if pi_ips else "127.0.0.1")
    if args.component == "authority":
        generate_dev_authority(root)
    elif args.component == "pi":
        ca_key, ca_cert = load_dev_authority(authority_root)
        generate_pi_security(
            root=root,
            ca_key=ca_key,
            ca_cert=ca_cert,
            sender_id=args.sender_id,
            key_id=args.key_id,
            pi_hostname=args.pi_hostname,
            pi_ip_addresses=pi_ips,
            trusted_server_public_key=Path(args.server_public_key) if args.server_public_key else None,
        )
    elif args.component == "server":
        ca_key, ca_cert = load_dev_authority(authority_root)
        generate_server_security(
            root=root,
            ca_key=ca_key,
            ca_cert=ca_cert,
            sender_id=args.sender_id,
            key_id=args.key_id,
            server_hostname=args.server_hostname,
            server_ip_addresses=server_ips,
            pi_public_key=Path(args.pi_public_key) if args.pi_public_key else None,
        )
    elif args.component == "trust-server":
        if not args.server_public_key:
            raise SystemExit("--server-public-key is required for --component trust-server")
        install_external_server_public_key_on_pi(root, Path(args.server_public_key), args.sender_id, args.key_id)
    elif args.component == "trust-pi":
        if not args.pi_public_key:
            raise SystemExit("--pi-public-key is required for --component trust-pi")
        install_external_pi_public_key_on_server(root, Path(args.pi_public_key))
    else:
        generate_dev_security(
            root=root,
            sender_id=args.sender_id,
            key_id=args.key_id,
            pi_hostname=args.pi_hostname,
            server_hostname=args.server_hostname,
            pi_ip_addresses=pi_ips,
            server_ip_addresses=server_ips,
        )

    if not args.no_config and args.component in ("all", "pi", "server"):
        write_default_configs(
            root=root,
            component=args.component,
            server_port=args.server_port,
            pi_port=args.pi_port,
            client_port=args.client_port,
            pi_listen_host=pi_listen_host,
            pi_connect_host=pi_connect_host,
        )

    print(f"Wrote development security files under {root.resolve()}")
    print(f"Sender id: {args.sender_id}")
    print(f"Key id: {args.key_id}")
    print("Run the Pi with files under pi/. Run the server with files under server/.")
    print("Keep authority/ca.key offline; it is only needed to issue more dev certs.")


def generate_dev_security(
    root: Path,
    sender_id: str = "server",
    key_id: str = "k1",
    pi_hostname: str = "raspberry-pi",
    server_hostname: str = "server",
    pi_ip_addresses: list[str] | None = None,
    server_ip_addresses: list[str] | None = None,
) -> None:
    """Generate all development certificates, keys, and peer key copies."""

    ca_key, ca_cert = generate_dev_authority(root)
    generate_pi_security(
        root=root,
        ca_key=ca_key,
        ca_cert=ca_cert,
        sender_id=sender_id,
        key_id=key_id,
        pi_hostname=pi_hostname,
        pi_ip_addresses=pi_ip_addresses,
    )
    generate_server_security(
        root=root,
        ca_key=ca_key,
        ca_cert=ca_cert,
        sender_id=sender_id,
        key_id=key_id,
        server_hostname=server_hostname,
        server_ip_addresses=server_ip_addresses,
    )
    install_server_public_key_on_pi(root, root, sender_id, key_id)
    install_pi_public_key_on_server(root, root)


def generate_dev_authority(root: Path) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Create and write the development CA under ``root/authority``."""

    authority_dir = root / "authority"
    authority_dir.mkdir(parents=True, exist_ok=True)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_cert = _build_ca_cert(ca_key)
    _write_private_key(authority_dir / "ca.key", ca_key)
    _write_cert(authority_dir / "ca.crt", ca_cert)
    return ca_key, ca_cert


def load_dev_authority(root: Path) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Load a development CA from ``root/authority``."""

    ca_key_path = root / "authority" / "ca.key"
    ca_cert_path = root / "authority" / "ca.crt"
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise TypeError(f"Authority key must be RSA: {ca_key_path}")
    return ca_key, ca_cert


def generate_pi_security(
    root: Path,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    sender_id: str = "server",
    key_id: str = "k1",
    pi_hostname: str = "raspberry-pi",
    pi_ip_addresses: list[str] | None = None,
    trusted_server_public_key: Path | None = None,
) -> None:
    """Generate Pi-side TLS and message-decryption material."""

    pi_certs_dir = root / "pi" / "certs"
    pi_sender_keys_dir = root / "pi" / "keys" / "senders"
    pi_private_keys_dir = root / "pi" / "keys" / "private"
    pi_exchange_dir = root / "exchange"
    for directory in (pi_certs_dir, pi_sender_keys_dir, pi_private_keys_dir, pi_exchange_dir):
        directory.mkdir(parents=True, exist_ok=True)

    _write_cert(pi_certs_dir / "ca.crt", ca_cert)
    pi_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pi_cert = _build_leaf_cert(
        ca_cert=ca_cert,
        ca_key=ca_key,
        leaf_key=pi_key,
        common_name=pi_hostname,
        dns_names=[pi_hostname, "localhost"],
        ip_addresses=_with_loopback(pi_ip_addresses),
        usages=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    _write_private_key(pi_certs_dir / "pi.key", pi_key)
    _write_cert(pi_certs_dir / "pi.crt", pi_cert)

    pi_x25519_private_key = x25519.X25519PrivateKey.generate()
    pi_x25519_public_key = pi_x25519_private_key.public_key()
    (pi_private_keys_dir / "pi_x25519.pem").write_bytes(
        pi_x25519_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (pi_exchange_dir / "pi_x25519.pub").write_bytes(
        pi_x25519_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    if trusted_server_public_key:
        shutil.copyfile(trusted_server_public_key, pi_sender_keys_dir / f"{sender_id}_{key_id}.pem")


def generate_server_security(
    root: Path,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    sender_id: str = "server",
    key_id: str = "k1",
    server_hostname: str = "server",
    server_ip_addresses: list[str] | None = None,
    pi_public_key: Path | None = None,
) -> None:
    """Generate server-side TLS and message-signing material."""

    server_certs_dir = root / "server" / "certs"
    server_private_keys_dir = root / "server" / "keys" / "private"
    server_public_keys_dir = root / "server" / "keys" / "public"
    server_exchange_dir = root / "exchange"
    for directory in (server_certs_dir, server_private_keys_dir, server_public_keys_dir, server_exchange_dir):
        directory.mkdir(parents=True, exist_ok=True)

    _write_cert(server_certs_dir / "ca.crt", ca_cert)
    server_tls_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_tls_cert = _build_leaf_cert(
        ca_cert=ca_cert,
        ca_key=ca_key,
        leaf_key=server_tls_key,
        common_name=server_hostname,
        dns_names=[server_hostname, "localhost"],
        ip_addresses=_with_loopback(server_ip_addresses),
        usages=[ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH],
    )
    _write_private_key(server_private_keys_dir / "server_tls.key", server_tls_key)
    _write_cert(server_private_keys_dir / "server_tls.crt", server_tls_cert)

    sender_private_key = ed25519.Ed25519PrivateKey.generate()
    sender_public_key = sender_private_key.public_key()
    sender_key_name = f"{sender_id}_{key_id}"
    (server_private_keys_dir / f"{sender_key_name}.pem").write_bytes(
        sender_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_bytes = sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (server_exchange_dir / f"{sender_key_name}.pem").write_bytes(public_key_bytes)

    if pi_public_key:
        shutil.copyfile(pi_public_key, server_public_keys_dir / "pi_x25519.pub")


def install_server_public_key_on_pi(pi_root: Path, server_root: Path, sender_id: str = "server", key_id: str = "k1") -> None:
    """Trust a generated server signing public key on a generated Pi root."""

    source = server_root / "exchange" / f"{sender_id}_{key_id}.pem"
    install_external_server_public_key_on_pi(pi_root, source, sender_id, key_id)


def install_external_server_public_key_on_pi(
    pi_root: Path,
    server_public_key: Path,
    sender_id: str = "server",
    key_id: str = "k1",
) -> None:
    """Trust an existing server signing public key on a generated Pi root."""

    target_dir = pi_root / "pi" / "keys" / "senders"
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(server_public_key, target_dir / f"{sender_id}_{key_id}.pem")


def install_pi_public_key_on_server(server_root: Path, pi_root: Path) -> None:
    """Install a generated Pi X25519 public key on a generated server root."""

    source = pi_root / "exchange" / "pi_x25519.pub"
    install_external_pi_public_key_on_server(server_root, source)


def install_external_pi_public_key_on_server(server_root: Path, pi_public_key: Path) -> None:
    """Install an existing Pi X25519 public key on a generated server root."""

    target_dir = server_root / "server" / "keys" / "public"
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(pi_public_key, target_dir / "pi_x25519.pub")


def build_pi_config(
    security_root: Path,
    port: int,
    forward_port: int,
    replay_db_path: Path,
    host: str = "127.0.0.1",
    forward_host: str = "127.0.0.1",
) -> dict[str, object]:
    """Build a Pi config that points at generated development security files."""

    return {
        "host": host,
        "port": port,
        "ca_cert_path": _security_path(security_root, "pi", "certs", "ca.crt"),
        "pi_cert_path": _security_path(security_root, "pi", "certs", "pi.crt"),
        "pi_key_path": _security_path(security_root, "pi", "certs", "pi.key"),
        "expected_recipient_id": "raspberry-pi",
        "sender_public_keys_dir": _security_path(security_root, "pi", "keys", "senders"),
        "x25519_private_key_path": _security_path(security_root, "pi", "keys", "private", "pi_x25519.pem"),
        "replay_db_path": _portable_path(replay_db_path),
        "max_message_size": MAX_MESSAGE_SIZE,
        "max_clock_skew_seconds": 300,
        "request_timeout_seconds": 5,
        "forward_host": forward_host,
        "forward_port": forward_port,
        "forward_timeout_seconds": 5,
    }


def build_server_config(
    server_security_root: Path,
    port: int,
    pi_port: int,
    trust_root: Path | None = None,
    signing_key_root: Path | None = None,
    encryption_key_root: Path | None = None,
    pi_host: str = "127.0.0.1",
    local_host: str | None = None,
) -> dict[str, object]:
    """Build a server config from generated development security files.

    Optional roots let tests model common failure modes without duplicating the
    generated path layout: wrong TLS trust, wrong signing key, or wrong Pi
    encryption key.
    """

    trust_root = trust_root or server_security_root
    signing_key_root = signing_key_root or server_security_root
    encryption_key_root = encryption_key_root or server_security_root
    return {
        "pi_host": pi_host,
        "pi_port": pi_port,
        "ca_cert_path": _security_path(trust_root, "server", "certs", "ca.crt"),
        "server_cert_path": _security_path(server_security_root, "server", "keys", "private", "server_tls.crt"),
        "server_key_path": _security_path(server_security_root, "server", "keys", "private", "server_tls.key"),
        "sender_id": "server",
        "recipient_id": "raspberry-pi",
        "key_id": "k1",
        "signing_private_key_path": _security_path(signing_key_root, "server", "keys", "private", "server_k1.pem"),
        "pi_x25519_public_key_path": _security_path(encryption_key_root, "server", "keys", "public", "pi_x25519.pub"),
        "max_message_size": MAX_MESSAGE_SIZE,
        "timeout_seconds": 5,
        "local_host": local_host,
        "local_port": port,
    }


def build_demi_client_config(
    security_root: Path,
    port: int,
    response: str,
    received_output_path: Path,
    host: str = "127.0.0.1",
) -> dict[str, object]:
    """Build a demi-client config from generated development security files."""

    return {
        "host": host,
        "port": port,
        "tls_cert_path": _security_path(security_root, "pi", "certs", "pi.crt"),
        "tls_key_path": _security_path(security_root, "pi", "certs", "pi.key"),
        "response": response,
        "received_output_path": _portable_path(received_output_path),
        "max_message_size": MAX_MESSAGE_SIZE,
    }


def write_config_file(path: Path, data: dict[str, object]) -> None:
    """Write a JSON runtime config file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


write_json_config = write_config_file


def write_default_configs(
    root: Path,
    component: str,
    server_port: int,
    pi_port: int,
    client_port: int,
    pi_listen_host: str = "127.0.0.1",
    pi_connect_host: str = "127.0.0.1",
) -> dict[str, Path]:
    """Write local JSON configs for generated development material."""

    config_dir = root / "config"
    written: dict[str, Path] = {}

    if component in ("all", "pi"):
        path = config_dir / "pi.local.json"
        write_config_file(
            path,
            build_pi_config(
                root,
                port=pi_port,
                forward_port=client_port,
                replay_db_path=root / "pi" / "replay.sqlite3",
                host=pi_listen_host,
            ),
        )
        written["pi"] = path

    if component in ("all", "server"):
        path = config_dir / "server.local.json"
        write_config_file(
            path,
            build_server_config(root, port=server_port, pi_port=pi_port, pi_host=pi_connect_host),
        )
        written["server"] = path

    if component in ("all", "pi"):
        path = config_dir / "client.local.json"
        write_config_file(
            path,
            build_demi_client_config(
                root,
                port=client_port,
                response="downstream client received payload",
                received_output_path=root / "demi_client_received.bin",
            ),
        )
        written["client"] = path

    return written


def _security_path(root: Path, *parts: str) -> str:
    return _portable_path(root.joinpath(*parts))


def _portable_path(path: Path) -> str:
    """Return a config path that works on Windows and POSIX runtimes."""

    return path.as_posix()


def _env(name: str, default: str) -> str:
    """Return a non-empty environment variable value or a default."""

    return os.getenv(name) or default


def _split_csv(value: str) -> list[str]:
    """Split a comma-separated environment value into non-empty strings."""

    return [part.strip() for part in value.split(",") if part.strip()]


def _unique_values(values: list[str] | None) -> list[str]:
    """Return unique non-empty values while preserving order."""

    unique: list[str] = []
    for value in values or []:
        value = value.strip()
        if value and value not in unique:
            unique.append(value)
    return unique


def _with_loopback(ip_addresses: list[str] | None) -> list[str]:
    """Always keep localhost cert support while adding real deployment IPs."""

    return _unique_values(["127.0.0.1", *(ip_addresses or [])])


def _build_ca_cert(ca_key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Build a self-signed development CA certificate.

    This CA signs both the Pi and server/client TLS certificates so mutual TLS
    can be tested locally without an external certificate authority.
    """

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Encryptor Daemon Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Encryptor Daemon Dev CA"),
        ]
    )
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


def _build_leaf_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    leaf_key: rsa.RSAPrivateKey,
    common_name: str,
    dns_names: list[str],
    ip_addresses: list[str],
    usages: list[x509.ObjectIdentifier],
) -> x509.Certificate:
    """Build a TLS certificate signed by the development CA.

    Args:
        ca_cert: Development CA certificate used as issuer.
        ca_key: Development CA private key used to sign the leaf certificate.
        leaf_key: Public/private keypair for the certificate subject.
        common_name: Human-readable subject name.
        dns_names: DNS Subject Alternative Names, e.g. `localhost`.
        ip_addresses: IP Subject Alternative Names, e.g. `127.0.0.1`.
        usages: Extended key usages such as serverAuth or clientAuth.

    Modern TLS clients verify Subject Alternative Names rather than relying on
    the Common Name. DNS SANs are used when connecting by hostname; IP SANs are
    used when connecting by numeric address.
    """

    now = datetime.now(UTC)
    # Include both DNSName and IPAddress SANs so the same dev certificate works
    # for `localhost`, the configured hostnames, and direct `127.0.0.1` testing.
    san = [x509.DNSName(name) for name in dns_names]
    san.extend(x509.IPAddress(ip_address(address)) for address in ip_addresses)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.ExtendedKeyUsage(usages), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    """Write an unencrypted PEM private key for local development.

    Production private keys should normally be created and stored by a proper
    secret-management or device-provisioning process.
    """

    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    """Write a PEM certificate."""

    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    main()
