"""Custom exceptions for the Secure Digital Document Vault.

Design rule
-----------
Every failure that happens while *opening* a container (wrong key, modified
ciphertext, modified tag, modified header/metadata, truncated or malformed
file, unsupported parameters inside the header...) is reported through one and
the same exception, :class:`DecryptionFailedError`, carrying one and the same
message.  Distinct exception types or messages for "bad key" versus "bad
integrity" would turn the vault into an *error oracle* that tells an attacker
which part of a forged container was rejected.

Errors raised while *creating* a container, or caused by invalid arguments
supplied by the local caller (wrong key length, non-serialisable metadata...),
are not attacker-controlled and may therefore be descriptive.
"""

from __future__ import annotations

__all__ = [
    "VaultError",
    "DecryptionFailedError",
    "InvalidKeyError",
    "InvalidMetadataError",
    "PlaintextTooLargeError",
    "UnsupportedAlgorithmError",
]

_GENERIC_DECRYPTION_MESSAGE = (
    "Decryption failed: the container is invalid, has been tampered with, "
    "or the key is incorrect."
)


class VaultError(Exception):
    """Base class for every error raised by the ``vault`` package."""


class DecryptionFailedError(VaultError):
    """Generic, oracle-free failure to authenticate/decrypt a vault container.

    Raised when AEAD tag verification fails (wrong owner key, modified
    ciphertext, tag, nonces, wrapped DEK or metadata) and also when the
    container cannot be parsed at all.  The message is fixed on purpose and
    the exception is raised *without* chaining the underlying cause, so no
    detail about the failing stage leaks through ``__cause__``/``__context__``.
    """

    def __init__(self) -> None:
        super().__init__(_GENERIC_DECRYPTION_MESSAGE)


class InvalidKeyError(VaultError, ValueError):
    """The owner key (KEK) supplied by the caller has the wrong type or length."""


class InvalidMetadataError(VaultError, ValueError):
    """User metadata cannot be serialised into the canonical JSON header."""


class PlaintextTooLargeError(VaultError, ValueError):
    """The input file exceeds the maximum size supported by one-shot AEAD."""


class UnsupportedAlgorithmError(VaultError, ValueError):
    """The requested AEAD algorithm is not in the vault's allow-list."""
