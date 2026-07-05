"""Length-prefixed socket framing shared by the Pi, server, and client."""

from __future__ import annotations

import socket

FRAME_HEADER_SIZE = 4


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly ``n`` bytes or raise a protocol error.

    TODO: loop until all bytes are received, and reject early peer closes.
    """

    raise NotImplementedError


def recv_framed_message(sock: socket.socket, max_size: int) -> bytes:
    """Receive one 4-byte length-prefixed message.

    TODO: parse the big-endian length, enforce ``max_size``, then read the body.
    """

    raise NotImplementedError


def send_framed_message(sock: socket.socket, data: bytes) -> None:
    """Send one 4-byte length-prefixed message.

    TODO: write the big-endian length followed by the payload bytes.
    """

    raise NotImplementedError
