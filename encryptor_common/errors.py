"""Shared exception hierarchy for expected protocol and daemon failures."""


class EncryptorError(Exception):
    """Base class for expected project errors."""


class ProtocolError(EncryptorError):
    """Raised when a framed message or envelope is malformed."""


class AuthenticationError(EncryptorError):
    """Raised when signature, certificate, or identity checks fail."""


class ReplayError(EncryptorError):
    """Raised when a message id has already been processed."""


class DecryptionError(EncryptorError):
    """Raised when ciphertext cannot be decrypted or authenticated."""


class ForwardingError(EncryptorError):
    """Raised when forwarding to the downstream destination fails."""

