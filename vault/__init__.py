"""Secure Digital Document Vault."""

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    InvalidMetadataError,
    PlaintextTooLargeError,
    UnsupportedAlgorithmError,
    VaultError,
)
from vault.symmetric import (
    DecryptedDocument,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
    generate_owner_key,
)

__all__ = [
    "DecryptedDocument",
    "DecryptionFailedError",
    "InvalidKeyError",
    "InvalidMetadataError",
    "PlaintextTooLargeError",
    "UnsupportedAlgorithmError",
    "VaultError",
    "decrypt_bytes",
    "decrypt_file",
    "encrypt_bytes",
    "encrypt_file",
    "generate_owner_key",
]

