"""Length-prefixed framing helpers shared by client and server code.

TCP is a byte stream, so one `send()` on one side does not equal one `recv()`
on the other side. This module defines a tiny message framing protocol:
4 bytes of big-endian length followed by exactly that many payload bytes.
"""

from __future__ import annotations

import socket
import struct

from .errors import ProtocolError

FRAME_HEADER_SIZE = 4


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly `n` bytes or raise `ProtocolError` if the peer closes.

    Args:
        sock: Connected socket or TLS socket.
        n: Number of bytes to read.

    Returns:
        Exactly `n` bytes.
    """

    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("Connection closed while receiving data")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_framed_message(sock: socket.socket, max_size: int) -> bytes:
    """Receive a 4-byte length followed by a bounded message body."""

    header = recv_exact(sock, FRAME_HEADER_SIZE)
    (size,) = struct.unpack("!I", header)
    if size == 0:
        raise ProtocolError("Empty framed message")
    if size > max_size:
        raise ProtocolError(f"Framed message exceeds max size: {size}")
    return recv_exact(sock, size)


def send_framed_message(sock: socket.socket, data: bytes) -> None:
    """Send bytes with a 4-byte big-endian length prefix."""

    sock.sendall(struct.pack("!I", len(data)) + data)

