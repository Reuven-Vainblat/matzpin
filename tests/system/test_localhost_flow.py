"""System test that runs the Pi and server entry points on localhost."""

from __future__ import annotations

from dataclasses import dataclass
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tools.generate_dev_security import (
    build_demi_client_config,
    build_pi_config,
    build_server_config,
    generate_dev_security,
    write_config_file,
)


ROOT = Path(__file__).resolve().parents[2]
MAX_MESSAGE_SIZE = 1_048_576
NO_OUTPUT = subprocess.DEVNULL


@dataclass(frozen=True)
class StartedProcess:
    process: subprocess.Popen[str]


@dataclass(frozen=True)
class SecurityRoots:
    trusted: Path
    other_server: Path


class LocalhostSystemTest(unittest.TestCase):
    def test_pi_main_then_server_main_round_trip_on_distinct_ports(self) -> None:
        message = "system test payload from the real client"
        downstream_response = "downstream client received payload"

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            roots = _generate_security_roots(workspace)
            received_output = Path(temp_dir) / "received.bin"
            flow = _prepare_test_configs(
                workspace,
                ports=_three_unused_ports(),
                pi_security_root=roots.trusted,
                server_security_root=roots.trusted,
                client_security_root=roots.trusted,
                downstream_response=downstream_response,
                received_output_path=received_output,
            )

            client = _start_client_main(flow["client_config"])
            pi = _start_pi_main(flow["pi_config"])

            try:
                _wait_for_bound_port(flow["client_port"], client, "demi client")
                _wait_for_bound_port(flow["pi_port"], pi, "Pi")
                server = _run_server_main(flow["server_config"], message)

                self.assertEqual(server.returncode, 0, server.stderr)
                self.assertEqual(server.stdout.strip(), downstream_response)
                self.assertEqual(received_output.read_bytes(), message.encode("utf-8"))
                self.assertEqual(_wait_for_process(client), 0)
            finally:
                _stop_process(pi)
                _stop_process(client)

    def test_rejects_server_with_untrusted_tls_certificate(self) -> None:
        """A server certificate from another CA must fail mutual TLS."""

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            roots = _generate_security_roots(workspace)
            received_output = workspace / "received.bin"
            flow = _prepare_test_configs(
                workspace,
                ports=_three_unused_ports(),
                pi_security_root=roots.trusted,
                server_security_root=roots.other_server,
                client_security_root=roots.trusted,
                trust_root=roots.trusted,
                received_output_path=received_output,
            )

            client = _start_client_main(flow["client_config"])
            pi = _start_pi_main(flow["pi_config"])

            try:
                _wait_for_bound_port(flow["client_port"], client, "demi client")
                _wait_for_bound_port(flow["pi_port"], pi, "Pi")
                server = _run_server_main(flow["server_config"], "bad tls client")

                self.assertNotEqual(server.returncode, 0)
                self.assertFalse(received_output.exists())
            finally:
                _stop_process(pi)
                _stop_process(client)

    def test_rejects_message_signed_by_unknown_server_key(self) -> None:
        """A valid TLS server still fails if its envelope signature is unknown."""

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            roots = _generate_security_roots(workspace)
            received_output = workspace / "received.bin"
            flow = _prepare_test_configs(
                workspace,
                ports=_three_unused_ports(),
                pi_security_root=roots.trusted,
                server_security_root=roots.trusted,
                client_security_root=roots.trusted,
                signing_key_root=roots.other_server,
                received_output_path=received_output,
            )

            client = _start_client_main(flow["client_config"])
            pi = _start_pi_main(flow["pi_config"])

            try:
                _wait_for_bound_port(flow["client_port"], client, "demi client")
                _wait_for_bound_port(flow["pi_port"], pi, "Pi")
                server = _run_server_main(flow["server_config"], "bad signature")

                self.assertNotEqual(server.returncode, 0)
                self.assertFalse(received_output.exists())
            finally:
                _stop_process(pi)
                _stop_process(client)

    def test_rejects_message_encrypted_to_wrong_pi_public_key(self) -> None:
        """A signed envelope fails if it was encrypted for another Pi key."""

        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            roots = _generate_security_roots(workspace)
            received_output = workspace / "received.bin"
            flow = _prepare_test_configs(
                workspace,
                ports=_three_unused_ports(),
                pi_security_root=roots.trusted,
                server_security_root=roots.trusted,
                client_security_root=roots.trusted,
                encryption_key_root=roots.other_server,
                received_output_path=received_output,
            )

            client = _start_client_main(flow["client_config"])
            pi = _start_pi_main(flow["pi_config"])

            try:
                _wait_for_bound_port(flow["client_port"], client, "demi client")
                _wait_for_bound_port(flow["pi_port"], pi, "Pi")
                server = _run_server_main(flow["server_config"], "bad encryption key")

                self.assertNotEqual(server.returncode, 0)
                self.assertFalse(received_output.exists())
            finally:
                _stop_process(pi)
                _stop_process(client)


def _start_pi_main(config_path: Path) -> StartedProcess:
    env = _child_env(ENCRYPTOR_PI_CONFIG=str(config_path))
    return _start_process(
        [sys.executable, "-m", "encryptor_pi.main"],
        env=env,
    )


def _start_client_main(config_path: Path) -> StartedProcess:
    return _start_process(
        [sys.executable, "-m", "encryptor_demi_client.main", "--config", str(config_path)],
    )


def _start_process(command: list[str], env: dict[str, str] | None = None) -> StartedProcess:
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=env or _child_env(),
        stdout=NO_OUTPUT,
        stderr=subprocess.PIPE,
        text=True,
    )
    return StartedProcess(process=process)


def _run_server_main(config_path: Path, message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "encryptor_server.main", message, "--config", str(config_path)],
        cwd=ROOT,
        capture_output=True,
        env=_child_env(),
        text=True,
        timeout=10,
    )


def _wait_for_bound_port(
    port: int,
    started: StartedProcess,
    name: str,
    timeout: float = 5.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if started.process.poll() is not None:
            _, stderr = _drain_process_output(started)
            raise RuntimeError(f"{name} exited before binding localhost:{port}\n{stderr}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                return
        time.sleep(0.05)
    raise TimeoutError(f"Timed out waiting for {name} on localhost:{port}")


def _wait_for_process(started: StartedProcess, timeout: float = 5.0) -> int:
    try:
        started.process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        started.process.kill()
        started.process.communicate(timeout=5)
    return started.process.returncode


def _stop_process(started: StartedProcess) -> None:
    process = started.process
    if process.poll() is not None:
        _drain_process_output(started)
        return
    process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def _drain_process_output(started: StartedProcess) -> tuple[str | None, str | None]:
    """Close subprocess pipes after a process exits."""

    return started.process.communicate(timeout=1)


def _three_unused_ports() -> tuple[int, int, int]:
    ports: list[int] = []
    sockets: list[socket.socket] = []
    try:
        for _ in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
            ports.append(int(sock.getsockname()[1]))
        return tuple(ports)
    finally:
        for sock in sockets:
            sock.close()


def _generate_security_roots(workspace: Path) -> SecurityRoots:
    """Create independent security roots for trusted and untrusted identities."""

    trusted = workspace / "trusted-security"
    other_server = workspace / "other-server-security"
    generate_dev_security(trusted)
    generate_dev_security(other_server)
    return SecurityRoots(trusted=trusted, other_server=other_server)


def _prepare_test_configs(
    workspace: Path,
    ports: tuple[int, int, int],
    pi_security_root: Path,
    server_security_root: Path,
    client_security_root: Path,
    received_output_path: Path,
    downstream_response: str = "downstream client received payload",
    trust_root: Path | None = None,
    signing_key_root: Path | None = None,
    encryption_key_root: Path | None = None,
) -> dict[str, Path | int]:
    """Prepare config paths for the three local test processes."""

    server_port, pi_port, client_port = ports
    pi_config = workspace / "pi.json"
    server_config = workspace / "server.json"
    client_config = workspace / "client.json"

    write_config_file(
        pi_config,
        build_pi_config(pi_security_root, pi_port, client_port, workspace / "replay.sqlite3"),
    )
    write_config_file(
        server_config,
        build_server_config(
            server_security_root=server_security_root,
            port=server_port,
            pi_port=pi_port,
            trust_root=trust_root,
            signing_key_root=signing_key_root,
            encryption_key_root=encryption_key_root,
        ),
    )
    write_config_file(
        client_config,
        build_demi_client_config(client_security_root, client_port, downstream_response, received_output_path),
    )
    return {
        "server_port": server_port,
        "pi_port": pi_port,
        "client_port": client_port,
        "pi_config": pi_config,
        "server_config": server_config,
        "client_config": client_config,
    }


def _child_env(**overrides: str) -> dict[str, str]:
    """Return a subprocess environment that avoids writing source bytecode."""

    return {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **overrides}


if __name__ == "__main__":
    unittest.main()
