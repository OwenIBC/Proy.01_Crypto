"""Symmetric authenticated encryption for the Secure Digital Document Vault (D2).

This module implements single-owner **envelope encryption** on top of an AEAD
cipher -- AES-256-GCM by default, ChaCha20-Poly1305 as a configurable
alternative -- using exclusively the high-level AEAD primitives of the
``cryptography`` package.  No cryptographic primitive is implemented here.

Scheme
------
1. A fresh, random 256-bit **DEK** (data-encryption key) is drawn from the OS
   CSPRNG for every file.
2. The DEK is wrapped (AEAD-encrypted) with the owner's 256-bit **KEK**.
3. The file content is AEAD-encrypted with the DEK.
4. A canonical JSON header (format version, algorithm parameters, UTC
   timestamp, optional original filename and optional user metadata) travels
   **in clear** but is bound to both AEAD operations as associated data.

Container layout (integers are big-endian)::

    +-------+---------+-----------+---------+-------------+---------+------------+-------+
    | Magic | Hdr len |  Header   |  Wrap   | Wrapped DEK | Payload | Ciphertext |  Tag  |
    | "SDDV"| uint32 N| JSON (N B)|  nonce  |  (32 + 16)  |  nonce  |   (M B)    | (16 B)|
    | (4 B) |  (4 B)  | canonical | (12 B)  |   (48 B)    | (12 B)  |            |       |
    +-------+---------+-----------+---------+-------------+---------+------------+-------+

Authentication bindings::

    AAD_wrap    = magic || hdr_len || header
    AAD_payload = magic || hdr_len || header || wrap_nonce || wrapped_dek || payload_nonce

``AAD_payload`` is *every byte that precedes the ciphertext*, so each single
byte of the container is covered by at least one authentication tag: flipping
any bit anywhere makes :func:`decrypt_file` fail with
:class:`~vault.exceptions.DecryptionFailedError`.

Failure semantics
-----------------
Decryption is performed entirely in memory and the output file is created only
after *both* tags have been verified.  On any failure nothing is written to
disk (no temporary file, no empty file, no partial plaintext).
"""

from __future__ import annotations

import errno
import json
import os
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    InvalidMetadataError,
    PlaintextTooLargeError,
    UnsupportedAlgorithmError,
)

__all__ = [
    "AES_256_GCM",
    "CHACHA20_POLY1305",
    "DEFAULT_ALGORITHM",
    "SUPPORTED_ALGORITHMS",
    "MAGIC",
    "FORMAT_VERSION",
    "KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "WRAPPED_DEK_SIZE",
    "MAX_HEADER_SIZE",
    "MAX_PLAINTEXT_SIZE",
    "DecryptedDocument",
    "generate_owner_key",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_file",
    "decrypt_file",
]

# --------------------------------------------------------------------------- #
# Format constants                                                            #
# --------------------------------------------------------------------------- #

MAGIC: Final[bytes] = b"SDDV"
"""Magic bytes identifying a Secure Digital Document Vault container."""

FORMAT_VERSION: Final[int] = 1
"""Version of the container format / header schema."""

KEY_SIZE: Final[int] = 32
"""Size in bytes of both the KEK and every DEK (256 bits)."""

NONCE_SIZE: Final[int] = 12
"""AEAD nonce size in bytes (96 bits, the size recommended for GCM)."""

TAG_SIZE: Final[int] = 16
"""AEAD authentication tag size in bytes (128 bits, never truncated)."""

WRAPPED_DEK_SIZE: Final[int] = KEY_SIZE + TAG_SIZE
"""Size of the wrapped DEK: AEAD ciphertext of a 32-byte key plus its tag."""

MAX_HEADER_SIZE: Final[int] = 64 * 1024
"""Upper bound for the JSON header; prevents memory-exhaustion on parsing."""

MAX_PLAINTEXT_SIZE: int = 2**31 - 1 - TAG_SIZE
"""Largest file accepted by the one-shot AEAD API of ``cryptography``.

The high-level AEAD classes process the whole message in a single call and
cap inputs at ``2**31 - 1`` bytes.  One-shot processing is deliberate: it is
what guarantees that no unauthenticated plaintext is ever released.
"""

_HEADER_LEN: Final[struct.Struct] = struct.Struct(">I")
_PREAMBLE_SIZE: Final[int] = len(MAGIC) + _HEADER_LEN.size
_FIXED_OVERHEAD: Final[int] = (
    _PREAMBLE_SIZE + NONCE_SIZE + WRAPPED_DEK_SIZE + NONCE_SIZE + TAG_SIZE
)

# --------------------------------------------------------------------------- #
# Algorithm allow-list                                                        #
# --------------------------------------------------------------------------- #

AES_256_GCM: Final[str] = "AES-256-GCM"
CHACHA20_POLY1305: Final[str] = "ChaCha20-Poly1305"
DEFAULT_ALGORITHM: Final[str] = AES_256_GCM

_Aead = Union[AESGCM, ChaCha20Poly1305]

# Both constructions use a 256-bit key, a 96-bit nonce and a 128-bit tag, so
# the container layout is identical whichever one is selected.
_ALGORITHMS: Final[Mapping[str, Callable[[bytes], _Aead]]] = MappingProxyType(
    {
        AES_256_GCM: AESGCM,
        CHACHA20_POLY1305: ChaCha20Poly1305,
    }
)
SUPPORTED_ALGORITHMS: Final[frozenset[str]] = frozenset(_ALGORITHMS)

_REQUIRED_HEADER_FIELDS: Final[frozenset[str]] = frozenset(
    {"version", "alg", "key_wrap", "key_bits", "nonce_bytes", "tag_bytes", "created_at"}
)
_OPTIONAL_HEADER_FIELDS: Final[frozenset[str]] = frozenset({"filename", "metadata"})

# --------------------------------------------------------------------------- #
# Public data types                                                           #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DecryptedDocument:
    """Result of a successful :func:`decrypt_bytes` call.

    Attributes:
        plaintext: The authenticated, decrypted file content.
        header: The parsed header.  It is returned only after both AEAD tags
            have been verified, so its content is authentic.
    """

    plaintext: bytes
    header: dict[str, Any]


@dataclass(frozen=True)
class _ContainerView:
    """Zero-trust parse of a container; nothing in here is authenticated yet."""

    header: dict[str, Any]
    wrap_aad: bytes
    wrap_nonce: bytes
    wrapped_dek: bytes
    payload_nonce: bytes
    payload_aad: bytes
    sealed_payload: memoryview  # ciphertext || tag


class _MalformedContainer(Exception):
    """Internal signal for structural errors; never escapes this module."""


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #


def generate_owner_key() -> bytes:
    """Return a fresh random 256-bit owner key (KEK) from the OS CSPRNG.

    Deriving the KEK from a passphrase (Argon2id/scrypt) is outside the scope
    of this deliverable; callers must store/derive this key securely.
    """
    return _random_bytes(KEY_SIZE)


def encrypt_bytes(
    plaintext: bytes,
    owner_key: bytes,
    *,
    metadata: Optional[Mapping[str, Any]] = None,
    filename: Optional[str] = None,
    algorithm: str = DEFAULT_ALGORITHM,
) -> bytes:
    """Seal ``plaintext`` into a vault container (in memory).

    Args:
        plaintext: Content to protect.
        owner_key: The owner's 32-byte key-encryption key (KEK).
        metadata: Optional JSON-serialisable mapping stored in the header.
            It is **authenticated but not encrypted** -- never put secrets in it.
        filename: Optional original file name stored (in clear) in the header.
        algorithm: ``"AES-256-GCM"`` (default) or ``"ChaCha20-Poly1305"``.

    Returns:
        The serialised container.

    Raises:
        InvalidKeyError: ``owner_key`` is not exactly 32 bytes.
        UnsupportedAlgorithmError: ``algorithm`` is not in the allow-list.
        InvalidMetadataError: ``metadata``/``filename`` cannot be encoded.
        PlaintextTooLargeError: ``plaintext`` exceeds :data:`MAX_PLAINTEXT_SIZE`.
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be a bytes-like object")
    kek = _validate_key(owner_key)
    aead = _resolve_algorithm(algorithm)
    if memoryview(plaintext).nbytes > MAX_PLAINTEXT_SIZE:
        raise PlaintextTooLargeError(
            f"input exceeds the maximum supported size of {MAX_PLAINTEXT_SIZE} bytes"
        )

    header = _encode_header(_build_header(algorithm, filename, metadata))
    wrap_aad = MAGIC + _HEADER_LEN.pack(len(header)) + header

    # Fresh single-use DEK per file: the payload nonce below is therefore used
    # exactly once under its key, which makes (key, nonce) reuse impossible.
    dek = _random_bytes(KEY_SIZE)

    wrap_nonce = _random_bytes(NONCE_SIZE)
    wrapped_dek = aead(kek).encrypt(wrap_nonce, dek, wrap_aad)

    payload_nonce = _random_bytes(NONCE_SIZE)
    payload_aad = wrap_aad + wrap_nonce + wrapped_dek + payload_nonce
    sealed_payload = aead(dek).encrypt(payload_nonce, plaintext, payload_aad)
    del dek  # best effort only: CPython cannot guarantee memory zeroisation

    # Container = everything authenticated as AAD, followed by ciphertext||tag.
    return payload_aad + sealed_payload


def decrypt_bytes(container: bytes, owner_key: bytes) -> DecryptedDocument:
    """Authenticate and open a vault container (in memory).

    Both tags (wrapped DEK and payload) are verified before anything is
    returned; the AEAD API never releases unauthenticated plaintext.

    Raises:
        InvalidKeyError: ``owner_key`` is not exactly 32 bytes (caller error).
        DecryptionFailedError: For *any* problem with the container itself:
            wrong key, modified byte anywhere, truncation, malformed header,
            unsupported parameters.  Always the same message, never chained.
    """
    if not isinstance(container, (bytes, bytearray)):
        raise TypeError("container must be bytes")
    kek = _validate_key(owner_key)

    document: Optional[DecryptedDocument] = None
    try:
        view = _parse_container(container)
        aead = _ALGORITHMS[view.header["alg"]]
        dek = aead(kek).decrypt(view.wrap_nonce, view.wrapped_dek, view.wrap_aad)
        plaintext = aead(dek).decrypt(
            view.payload_nonce, view.sealed_payload, view.payload_aad
        )
        del dek
        document = DecryptedDocument(plaintext=plaintext, header=view.header)
    except (
        InvalidTag,
        _MalformedContainer,
        KeyError,
        TypeError,
        ValueError,  # includes json.JSONDecodeError and UnicodeDecodeError
        OverflowError,
        RecursionError,  # pathologically nested JSON
        struct.error,
    ):
        document = None

    # Raised *outside* the ``except`` block on purpose: the generic error then
    # carries neither ``__cause__`` nor ``__context__``, so the failing stage
    # (parse vs. key unwrap vs. payload tag) is never exposed to callers.
    if document is None:
        raise DecryptionFailedError()
    return document


def encrypt_file(
    file_path: Path,
    owner_key: bytes,
    output_path: Path,
    metadata: Optional[dict[str, Any]] = None,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
    include_filename: bool = True,
) -> Path:
    """Encrypt ``file_path`` into a new vault container at ``output_path``.

    Args:
        file_path: File to protect.
        owner_key: The owner's 32-byte KEK.
        output_path: Destination; must not exist (never overwritten).
        metadata: Optional JSON-serialisable dict, authenticated but stored
            in clear inside the header.
        algorithm: ``"AES-256-GCM"`` (default) or ``"ChaCha20-Poly1305"``.
        include_filename: Store ``file_path.name`` in the header (in clear).
            Set to ``False`` when the file name itself is sensitive.

    Returns:
        ``output_path``.

    Raises:
        FileExistsError: ``output_path`` already exists.
        InvalidKeyError, InvalidMetadataError, UnsupportedAlgorithmError,
        PlaintextTooLargeError: see :func:`encrypt_bytes`.
        OSError: I/O failure; any partially written output is removed.
    """
    source = Path(file_path)
    destination = Path(output_path)
    kek = _validate_key(owner_key)
    _resolve_algorithm(algorithm)
    _ensure_absent(destination)

    plaintext = _read_limited(source, MAX_PLAINTEXT_SIZE)
    if plaintext is None:
        raise PlaintextTooLargeError(
            f"input exceeds the maximum supported size of {MAX_PLAINTEXT_SIZE} bytes"
        )

    container = encrypt_bytes(
        plaintext,
        kek,
        metadata=metadata,
        filename=source.name if include_filename else None,
        algorithm=algorithm,
    )
    _write_new_file(destination, container)
    return destination


def decrypt_file(vault_file_path: Path, owner_key: bytes, output_path: Path) -> Path:
    """Authenticate and decrypt a vault container into ``output_path``.

    The container is fully verified in memory first; ``output_path`` is created
    only after successful authentication.  On failure, nothing is written.

    Returns:
        ``output_path``.

    Raises:
        DecryptionFailedError: Wrong key or invalid/tampered container.
        InvalidKeyError: ``owner_key`` is not exactly 32 bytes.
        FileExistsError: ``output_path`` already exists (never overwritten).
        OSError: I/O failure reading the input or writing the output; any
            partially written output is removed.
    """
    source = Path(vault_file_path)
    destination = Path(output_path)
    kek = _validate_key(owner_key)
    _ensure_absent(destination)

    max_container = MAX_PLAINTEXT_SIZE + MAX_HEADER_SIZE + _FIXED_OVERHEAD
    container = _read_limited(source, max_container)
    if container is None:
        raise DecryptionFailedError()

    document = decrypt_bytes(container, kek)  # disk untouched if this raises
    _write_new_file(destination, document.plaintext)
    return destination


# --------------------------------------------------------------------------- #
# Internal helpers: keys, algorithms, randomness                              #
# --------------------------------------------------------------------------- #


def _random_bytes(size: int) -> bytes:
    """Single source of randomness: the operating system CSPRNG."""
    return os.urandom(size)


def _validate_key(owner_key: object) -> bytes:
    if not isinstance(owner_key, (bytes, bytearray, memoryview)):
        raise InvalidKeyError("owner_key must be a bytes-like object")
    key = bytes(owner_key)
    if len(key) != KEY_SIZE:
        # AESGCM would silently accept 16/24-byte keys; the vault mandates 256 bits.
        raise InvalidKeyError(
            f"owner_key must be exactly {KEY_SIZE} bytes (256 bits), got {len(key)}"
        )
    return key


def _resolve_algorithm(algorithm: str) -> Callable[[bytes], _Aead]:
    try:
        return _ALGORITHMS[algorithm]
    except (KeyError, TypeError):
        supported = ", ".join(sorted(SUPPORTED_ALGORITHMS))
        raise UnsupportedAlgorithmError(
            f"unsupported algorithm {algorithm!r}; choose one of: {supported}"
        ) from None


# --------------------------------------------------------------------------- #
# Internal helpers: header                                                    #
# --------------------------------------------------------------------------- #


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(value: Any) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only, no NaN/Inf."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _build_header(
    algorithm: str, filename: Optional[str], metadata: Optional[Mapping[str, Any]]
) -> dict[str, Any]:
    header: dict[str, Any] = {
        "version": FORMAT_VERSION,
        "alg": algorithm,
        "key_wrap": algorithm,
        "key_bits": KEY_SIZE * 8,
        "nonce_bytes": NONCE_SIZE,
        "tag_bytes": TAG_SIZE,
        "created_at": _utc_timestamp(),
    }
    if filename is not None:
        if not isinstance(filename, str):
            raise InvalidMetadataError("filename must be a string")
        header["filename"] = filename
    if metadata is not None:
        if not isinstance(metadata, Mapping):
            raise InvalidMetadataError("metadata must be a mapping (dict)")
        header["metadata"] = dict(metadata)
    return header


def _encode_header(header: dict[str, Any]) -> bytes:
    try:
        encoded = _canonical_json(header)
        round_trip = json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidMetadataError(
            "metadata must be JSON-serialisable (str keys, finite numbers, "
            "no circular references)"
        ) from exc
    if round_trip != header:
        raise InvalidMetadataError(
            "metadata does not survive a canonical JSON round-trip "
            "(use str keys and lists instead of tuples)"
        )
    if len(encoded) > MAX_HEADER_SIZE:
        raise InvalidMetadataError(
            f"encoded header exceeds the maximum of {MAX_HEADER_SIZE} bytes"
        )
    return encoded


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _MalformedContainer
        result[key] = value
    return result


def _reject_constant(_: str) -> Any:
    raise _MalformedContainer  # NaN / Infinity / -Infinity


def _decode_header(raw: bytes) -> dict[str, Any]:
    """Strictly parse and validate the (not yet authenticated) header."""
    header = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    if not isinstance(header, dict):
        raise _MalformedContainer
    # Only the exact canonical encoding is accepted (defence in depth against
    # parser-differential tricks; the raw bytes are authenticated anyway).
    if _canonical_json(header) != raw:
        raise _MalformedContainer
    _validate_header_schema(header)
    return header


def _validate_header_schema(header: dict[str, Any]) -> None:
    fields = header.keys()
    if not _REQUIRED_HEADER_FIELDS <= fields:
        raise _MalformedContainer
    if not fields <= _REQUIRED_HEADER_FIELDS | _OPTIONAL_HEADER_FIELDS:
        raise _MalformedContainer

    algorithm = header["alg"]
    if not isinstance(algorithm, str) or algorithm not in _ALGORITHMS:
        raise _MalformedContainer
    if header["key_wrap"] != algorithm:
        raise _MalformedContainer

    expected_ints = {
        "version": FORMAT_VERSION,
        "key_bits": KEY_SIZE * 8,
        "nonce_bytes": NONCE_SIZE,
        "tag_bytes": TAG_SIZE,
    }
    for field, expected in expected_ints.items():
        value = header[field]
        # ``type(...) is int`` rejects ``True``/``False``, which equal 1/0.
        if type(value) is not int or value != expected:
            raise _MalformedContainer

    if not isinstance(header["created_at"], str):
        raise _MalformedContainer
    if "filename" in header and not isinstance(header["filename"], str):
        raise _MalformedContainer
    if "metadata" in header and not isinstance(header["metadata"], dict):
        raise _MalformedContainer


# --------------------------------------------------------------------------- #
# Internal helpers: container parsing                                         #
# --------------------------------------------------------------------------- #


def _parse_container(container: bytes) -> _ContainerView:
    data = memoryview(container)
    total = len(data)
    if total < _FIXED_OVERHEAD:
        raise _MalformedContainer
    if bytes(data[: len(MAGIC)]) != MAGIC:
        raise _MalformedContainer

    (header_len,) = _HEADER_LEN.unpack_from(data, len(MAGIC))
    if not 0 < header_len <= MAX_HEADER_SIZE:
        raise _MalformedContainer
    if total < _FIXED_OVERHEAD + header_len:
        raise _MalformedContainer

    pos = _PREAMBLE_SIZE
    header = _decode_header(bytes(data[pos : pos + header_len]))
    pos += header_len
    wrap_aad = bytes(data[:pos])

    wrap_nonce = bytes(data[pos : pos + NONCE_SIZE])
    pos += NONCE_SIZE
    wrapped_dek = bytes(data[pos : pos + WRAPPED_DEK_SIZE])
    pos += WRAPPED_DEK_SIZE
    payload_nonce = bytes(data[pos : pos + NONCE_SIZE])
    pos += NONCE_SIZE
    payload_aad = bytes(data[:pos])

    return _ContainerView(
        header=header,
        wrap_aad=wrap_aad,
        wrap_nonce=wrap_nonce,
        wrapped_dek=wrapped_dek,
        payload_nonce=payload_nonce,
        payload_aad=payload_aad,
        sealed_payload=data[pos:],  # length >= TAG_SIZE guaranteed above
    )


# --------------------------------------------------------------------------- #
# Internal helpers: file I/O                                                  #
# --------------------------------------------------------------------------- #


def _ensure_absent(path: Path) -> None:
    # ``lexists`` also catches dangling symlinks.
    if os.path.lexists(path):
        raise FileExistsError(errno.EEXIST, "refusing to overwrite existing path", str(path))


def _read_limited(path: Path, limit: int) -> Optional[bytes]:
    """Read ``path`` entirely, or return ``None`` if it exceeds ``limit`` bytes."""
    with path.open("rb") as handle:
        if os.fstat(handle.fileno()).st_size > limit:
            return None
        data = handle.read(limit + 1)  # re-checked: the file may grow meanwhile
    return None if len(data) > limit else data


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _write_new_file(path: Path, data: bytes) -> None:
    """Create ``path`` exclusively (mode 0600) and write ``data`` to it.

    ``O_EXCL`` guarantees we never clobber or follow an existing file/symlink.
    If anything fails after creation the partial file is removed, so a failed
    call never leaves an empty or truncated output behind.
    """
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags, 0o600)
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
