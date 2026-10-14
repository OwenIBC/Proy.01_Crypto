"""Test-suite for ``vault.symmetric`` (Deliverable D2).

The container layout is re-parsed here *independently* of the implementation
so that the tests also pin down the on-disk format required by the spec::

    Magic(4) | HeaderLen(4) | Header(N) | WrapNonce(12) | WrappedDEK(48)
             | PayloadNonce(12) | Ciphertext(M) | Tag(16)
"""

from __future__ import annotations

import ast
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from vault import symmetric
from vault.exceptions import (
    DecryptionFailedError,
    InvalidKeyError,
    InvalidMetadataError,
    PlaintextTooLargeError,
    UnsupportedAlgorithmError,
    VaultError,
)
from vault.symmetric import (
    AES_256_GCM,
    CHACHA20_POLY1305,
    SUPPORTED_ALGORITHMS,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
    generate_owner_key,
)

MAGIC = b"SDDV"
KEY_LEN = 32
NONCE_LEN = 12
WRAPPED_DEK_LEN = 48
TAG_LEN = 16
ALGORITHMS = sorted(SUPPORTED_ALGORITHMS)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Layout:
    """Independent parse of a container, with byte offsets of every field."""

    header_len: int
    header: bytes
    wrap_nonce: bytes
    wrapped_dek: bytes
    payload_nonce: bytes
    ciphertext: bytes
    tag: bytes
    header_start: int
    wrap_nonce_start: int
    wrapped_dek_start: int
    payload_nonce_start: int
    ciphertext_start: int
    tag_start: int

    @property
    def header_json(self) -> dict:
        return json.loads(self.header)


def split_container(blob: bytes) -> Layout:
    assert blob[:4] == MAGIC
    (header_len,) = struct.unpack(">I", blob[4:8])
    header_start = 8
    wrap_nonce_start = header_start + header_len
    wrapped_dek_start = wrap_nonce_start + NONCE_LEN
    payload_nonce_start = wrapped_dek_start + WRAPPED_DEK_LEN
    ciphertext_start = payload_nonce_start + NONCE_LEN
    tag_start = len(blob) - TAG_LEN
    assert tag_start >= ciphertext_start
    return Layout(
        header_len=header_len,
        header=blob[header_start:wrap_nonce_start],
        wrap_nonce=blob[wrap_nonce_start:wrapped_dek_start],
        wrapped_dek=blob[wrapped_dek_start:payload_nonce_start],
        payload_nonce=blob[payload_nonce_start:ciphertext_start],
        ciphertext=blob[ciphertext_start:tag_start],
        tag=blob[tag_start:],
        header_start=header_start,
        wrap_nonce_start=wrap_nonce_start,
        wrapped_dek_start=wrapped_dek_start,
        payload_nonce_start=payload_nonce_start,
        ciphertext_start=ciphertext_start,
        tag_start=tag_start,
    )


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def replace_header(blob: bytes, new_header: bytes) -> bytes:
    """Swap the header and fix the length prefix so the container stays parseable."""
    layout = split_container(blob)
    rest = blob[layout.wrap_nonce_start :]
    return MAGIC + struct.pack(">I", len(new_header)) + new_header + rest


def flip_bit(blob: bytes, index: int, bit: int = 0) -> bytes:
    mutated = bytearray(blob)
    mutated[index] ^= 1 << bit
    return bytes(mutated)


def listing(directory: Path) -> set[str]:
    return {entry.name for entry in directory.iterdir()}


def assert_decrypt_fails_cleanly(vault_path: Path, key: bytes, out: Path) -> None:
    """Decryption must raise the generic error and leave the directory untouched."""
    before = listing(out.parent)
    with pytest.raises(DecryptionFailedError):
        decrypt_file(vault_path, key, out)
    assert not os.path.lexists(out), "no output file may be created on failure"
    assert listing(out.parent) == before, "no temporary/residual files allowed"


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture
def owner_key() -> bytes:
    return generate_owner_key()


@pytest.fixture
def plain_dir(tmp_path: Path) -> Path:
    d = tmp_path / "plain"
    d.mkdir()
    return d


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    d = tmp_path / "out"
    d.mkdir()
    return d


@pytest.fixture
def sample_file(plain_dir: Path) -> Path:
    path = plain_dir / "informe_confidencial.pdf"
    path.write_bytes(b"%PDF-1.7\n" + os.urandom(4096) + b"\n%%EOF\n")
    return path


@pytest.fixture
def vault_file(sample_file: Path, owner_key: bytes, tmp_path: Path) -> Path:
    return encrypt_file(sample_file, owner_key, tmp_path / "doc.vault", {"owner": "alice"})


# --------------------------------------------------------------------------- #
# 1. Full cycle                                                               #
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    @pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 4096, 1024 * 1024 + 3])
    def test_file_roundtrip_is_byte_identical(
        self, plain_dir: Path, out_dir: Path, owner_key: bytes, algorithm: str, size: int
    ) -> None:
        original = plain_dir / f"file_{size}.bin"
        original.write_bytes(os.urandom(size))

        sealed = encrypt_file(original, owner_key, out_dir / "f.vault", algorithm=algorithm)
        restored = decrypt_file(sealed, owner_key, out_dir / "restored.bin")

        assert restored == out_dir / "restored.bin"
        assert restored.read_bytes() == original.read_bytes()
        assert (
            hashlib.sha256(restored.read_bytes()).digest()
            == hashlib.sha256(original.read_bytes()).digest()
        )

    def test_default_algorithm_is_aes_256_gcm(self, vault_file: Path) -> None:
        header = split_container(vault_file.read_bytes()).header_json
        assert header["alg"] == AES_256_GCM
        assert header["key_wrap"] == AES_256_GCM

    def test_accepts_str_paths(self, sample_file: Path, out_dir: Path, owner_key: bytes) -> None:
        sealed = encrypt_file(str(sample_file), owner_key, str(out_dir / "s.vault"))  # type: ignore[arg-type]
        restored = decrypt_file(str(sealed), owner_key, str(out_dir / "s.out"))  # type: ignore[arg-type]
        assert Path(restored).read_bytes() == sample_file.read_bytes()

    def test_container_layout_matches_spec(self, sample_file: Path, vault_file: Path) -> None:
        blob = vault_file.read_bytes()
        layout = split_container(blob)
        plaintext_len = sample_file.stat().st_size

        assert blob[:4] == MAGIC
        assert len(layout.wrap_nonce) == NONCE_LEN
        assert len(layout.wrapped_dek) == WRAPPED_DEK_LEN
        assert len(layout.payload_nonce) == NONCE_LEN
        assert len(layout.tag) == TAG_LEN
        assert len(layout.ciphertext) == plaintext_len  # GCM is length-preserving
        assert len(blob) == 4 + 4 + layout.header_len + 12 + 48 + 12 + plaintext_len + 16

    def test_header_is_canonical_cleartext_json(self, vault_file: Path) -> None:
        layout = split_container(vault_file.read_bytes())
        header = layout.header_json
        assert layout.header == canonical(header)
        assert header["version"] == 1
        assert header["key_bits"] == 256
        assert header["nonce_bytes"] == 12
        assert header["tag_bytes"] == 16
        assert header["filename"] == "informe_confidencial.pdf"
        assert header["metadata"] == {"owner": "alice"}
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", header["created_at"])

    def test_plaintext_is_not_visible_in_container(self, plain_dir: Path, tmp_path: Path, owner_key: bytes) -> None:
        secret = b"TOP-SECRET-MARKER-" * 64
        source = plain_dir / "secret.txt"
        source.write_bytes(secret)
        blob = encrypt_file(source, owner_key, tmp_path / "s.vault").read_bytes()
        assert b"TOP-SECRET-MARKER" not in blob

    def test_authenticated_header_returned_by_decrypt_bytes(self, owner_key: bytes) -> None:
        metadata = {"case": "2026-17", "tags": ["legal", "nda"], "pages": 12, "draft": False}
        blob = encrypt_bytes(b"data", owner_key, metadata=metadata, filename="nda.docx")
        document = decrypt_bytes(blob, owner_key)
        assert document.plaintext == b"data"
        assert document.header["metadata"] == metadata
        assert document.header["filename"] == "nda.docx"

    def test_unicode_metadata_and_filename(self, plain_dir: Path, tmp_path: Path, owner_key: bytes) -> None:
        source = plain_dir / "contraseña_año_🔐.txt"
        source.write_bytes(b"x")
        sealed = encrypt_file(source, owner_key, tmp_path / "u.vault", {"autor": "Iñaki Peña"})
        header = decrypt_bytes(sealed.read_bytes(), owner_key).header
        assert header["filename"] == "contraseña_año_🔐.txt"
        assert header["metadata"] == {"autor": "Iñaki Peña"}

    def test_filename_can_be_omitted(self, sample_file: Path, tmp_path: Path, owner_key: bytes) -> None:
        sealed = encrypt_file(sample_file, owner_key, tmp_path / "n.vault", include_filename=False)
        blob = sealed.read_bytes()
        assert "filename" not in split_container(blob).header_json
        assert sample_file.name.encode() not in blob

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_outputs_are_owner_only(self, vault_file: Path, out_dir: Path, owner_key: bytes) -> None:
        restored = decrypt_file(vault_file, owner_key, out_dir / "r.pdf")
        assert stat.S_IMODE(vault_file.stat().st_mode) & 0o077 == 0
        assert stat.S_IMODE(restored.stat().st_mode) & 0o077 == 0


# --------------------------------------------------------------------------- #
# 2. Wrong key                                                                #
# --------------------------------------------------------------------------- #


class TestWrongKey:
    def test_random_wrong_key_fails_without_output(
        self, vault_file: Path, out_dir: Path
    ) -> None:
        assert_decrypt_fails_cleanly(vault_file, generate_owner_key(), out_dir / "x.pdf")

    @pytest.mark.parametrize("bit_position", [0, 7, 128, 255])
    def test_key_differing_by_one_bit_fails(
        self, vault_file: Path, out_dir: Path, owner_key: bytes, bit_position: int
    ) -> None:
        near_key = flip_bit(owner_key, bit_position // 8, bit_position % 8)
        assert_decrypt_fails_cleanly(vault_file, near_key, out_dir / "x.pdf")

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_wrong_key_fails_for_every_algorithm(self, owner_key: bytes, algorithm: str) -> None:
        blob = encrypt_bytes(b"payload", owner_key, algorithm=algorithm)
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(blob, generate_owner_key())

    @pytest.mark.parametrize("length", [0, 1, 16, 24, 31, 33, 64])
    def test_invalid_key_length_is_rejected(
        self, sample_file: Path, vault_file: Path, out_dir: Path, length: int
    ) -> None:
        bad_key = os.urandom(length)
        with pytest.raises(InvalidKeyError):
            encrypt_file(sample_file, bad_key, out_dir / "a.vault")
        with pytest.raises(InvalidKeyError):
            decrypt_file(vault_file, bad_key, out_dir / "a.out")
        assert listing(out_dir) == set()

    @pytest.mark.parametrize("bad_key", ["a" * 32, None, 12345, [0] * 32])
    def test_non_bytes_key_is_rejected(self, owner_key: bytes, bad_key: object) -> None:
        with pytest.raises(InvalidKeyError):
            encrypt_bytes(b"x", bad_key)  # type: ignore[arg-type]
        blob = encrypt_bytes(b"x", owner_key)
        with pytest.raises(InvalidKeyError):
            decrypt_bytes(blob, bad_key)  # type: ignore[arg-type]

    def test_bytearray_key_is_accepted(self, owner_key: bytes) -> None:
        blob = encrypt_bytes(b"x", bytearray(owner_key))
        assert decrypt_bytes(blob, memoryview(owner_key)).plaintext == b"x"


# --------------------------------------------------------------------------- #
# 3. Tampered ciphertext (and every other byte of the container)              #
# --------------------------------------------------------------------------- #


class TestCiphertextTampering:
    def test_random_single_bit_flip_in_ciphertext(
        self, vault_file: Path, out_dir: Path, owner_key: bytes, tmp_path: Path
    ) -> None:
        blob = vault_file.read_bytes()
        layout = split_container(blob)
        ct_len = layout.tag_start - layout.ciphertext_start
        for attempt in range(25):
            index = layout.ciphertext_start + secrets.randbelow(ct_len)
            tampered = tmp_path / f"tampered_{attempt}.vault"
            tampered.write_bytes(flip_bit(blob, index, secrets.randbelow(8)))
            assert_decrypt_fails_cleanly(tampered, owner_key, out_dir / "x.pdf")

    @pytest.mark.parametrize(
        "region",
        ["ciphertext_first", "ciphertext_last", "tag_first", "tag_last",
         "payload_nonce", "wrapped_dek", "wrap_nonce"],
    )
    def test_bit_flip_in_each_binary_region(
        self, vault_file: Path, owner_key: bytes, region: str
    ) -> None:
        blob = vault_file.read_bytes()
        layout = split_container(blob)
        index = {
            "ciphertext_first": layout.ciphertext_start,
            "ciphertext_last": layout.tag_start - 1,
            "tag_first": layout.tag_start,
            "tag_last": len(blob) - 1,
            "payload_nonce": layout.payload_nonce_start + 5,
            "wrapped_dek": layout.wrapped_dek_start + 20,
            "wrap_nonce": layout.wrap_nonce_start + 3,
        }[region]
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(flip_bit(blob, index, 7), owner_key)

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_exhaustive_every_bit_of_container_is_authenticated(
        self, owner_key: bytes, algorithm: str
    ) -> None:
        """Flip every single bit of a small container: all variants must fail."""
        blob = encrypt_bytes(b"short secret document", owner_key, filename="a.txt", algorithm=algorithm)
        survivors = []
        for index in range(len(blob)):
            for bit in range(8):
                try:
                    decrypt_bytes(flip_bit(blob, index, bit), owner_key)
                except DecryptionFailedError:
                    continue
                survivors.append((index, bit))
        assert survivors == [], f"unauthenticated bits found: {survivors[:10]}"

    @pytest.mark.parametrize("cut", [0, 1, 4, 8, 50, -1, -16, -17])
    def test_truncated_container_fails(self, owner_key: bytes, cut: int) -> None:
        blob = encrypt_bytes(b"some content here", owner_key)
        truncated = blob[:cut] if cut > 0 else (b"" if cut == 0 else blob[:cut])
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(truncated, owner_key)

    def test_appended_bytes_fail(self, owner_key: bytes) -> None:
        blob = encrypt_bytes(b"content", owner_key)
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(blob + b"\x00", owner_key)

    def test_swapping_wrapped_dek_between_containers_fails(self, owner_key: bytes) -> None:
        a = encrypt_bytes(b"document A", owner_key)
        b = encrypt_bytes(b"document B", owner_key)
        la, lb = split_container(a), split_container(b)
        franken = (
            a[: la.wrap_nonce_start]
            + lb.wrap_nonce + lb.wrapped_dek
            + a[la.payload_nonce_start :]
        )
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(franken, owner_key)

    def test_swapping_payload_between_containers_fails(self, owner_key: bytes) -> None:
        a = encrypt_bytes(b"document A", owner_key)
        b = encrypt_bytes(b"document B", owner_key)
        la, lb = split_container(a), split_container(b)
        franken = a[: la.payload_nonce_start] + b[lb.payload_nonce_start :]
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(franken, owner_key)

    @pytest.mark.parametrize(
        "garbage",
        [b"", b"SDDV", b"not a vault at all", b"SDDV" + b"\xff" * 4 + b"\x00" * 200, os.urandom(512)],
    )
    def test_arbitrary_input_is_rejected(self, owner_key: bytes, garbage: bytes) -> None:
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(garbage, owner_key)


# --------------------------------------------------------------------------- #
# 4. Tampered metadata (AAD)                                                  #
# --------------------------------------------------------------------------- #


def _set(field, value):
    def mutate(h: dict) -> None:
        h[field] = value
    return mutate


def _delete(field):
    def mutate(h: dict) -> None:
        del h[field]
    return mutate


def _set_metadata(key, value):
    def mutate(h: dict) -> None:
        h["metadata"][key] = value
    return mutate


HEADER_MUTATIONS = {
    "rename_file": _set("filename", "inocente.txt"),
    "backdate_timestamp": _set("created_at", "1999-01-01T00:00:00Z"),
    "change_metadata_value": _set_metadata("owner", "mallory"),
    "inject_metadata_key": _set_metadata("admin", True),
    "drop_filename": _delete("filename"),
    "drop_metadata": _delete("metadata"),
    "downgrade_algorithm": _set("alg", CHACHA20_POLY1305),
    "change_both_algorithms": lambda h: h.update(alg=CHACHA20_POLY1305, key_wrap=CHACHA20_POLY1305),
    "bump_version": _set("version", 2),
    "change_key_bits": _set("key_bits", 128),
    "change_nonce_size": _set("nonce_bytes", 16),
    "add_unknown_field": _set("compression", "none"),
    "bool_instead_of_int": _set("version", True),
}


class TestMetadataTampering:
    @pytest.mark.parametrize("mutation", sorted(HEADER_MUTATIONS))
    def test_semantic_header_modification_fails(
        self, vault_file: Path, owner_key: bytes, out_dir: Path, tmp_path: Path, mutation: str
    ) -> None:
        blob = vault_file.read_bytes()
        header = split_container(blob).header_json
        HEADER_MUTATIONS[mutation](header)
        tampered = tmp_path / "tampered.vault"
        tampered.write_bytes(replace_header(blob, canonical(header)))
        assert_decrypt_fails_cleanly(tampered, owner_key, out_dir / "x.pdf")

    def test_every_header_byte_is_authenticated(self, vault_file: Path, owner_key: bytes) -> None:
        blob = vault_file.read_bytes()
        layout = split_container(blob)
        for index in range(0, layout.wrap_nonce_start):  # magic + length + header
            with pytest.raises(DecryptionFailedError):
                decrypt_bytes(flip_bit(blob, index, 1), owner_key)

    def test_semantically_equal_but_non_canonical_header_fails(
        self, vault_file: Path, owner_key: bytes
    ) -> None:
        blob = vault_file.read_bytes()
        header = split_container(blob).header_json
        pretty = json.dumps(header, indent=2, sort_keys=False).encode()
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(replace_header(blob, pretty), owner_key)

    def test_duplicate_keys_in_header_fail(self, vault_file: Path, owner_key: bytes) -> None:
        blob = vault_file.read_bytes()
        raw = split_container(blob).header
        duplicated = raw[:-1] + b',"version":1}'
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(replace_header(blob, duplicated), owner_key)

    @pytest.mark.parametrize("delta", [-1, 1, 1000, 2**31])
    def test_header_length_field_tampering_fails(
        self, vault_file: Path, owner_key: bytes, delta: int
    ) -> None:
        blob = vault_file.read_bytes()
        (length,) = struct.unpack(">I", blob[4:8])
        forged = blob[:4] + struct.pack(">I", (length + delta) % 2**32) + blob[8:]
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(forged, owner_key)

    def test_header_from_another_container_fails(self, owner_key: bytes) -> None:
        a = encrypt_bytes(b"A", owner_key, metadata={"id": 1})
        b = encrypt_bytes(b"B", owner_key, metadata={"id": 2})
        with pytest.raises(DecryptionFailedError):
            decrypt_bytes(replace_header(a, split_container(b).header), owner_key)


# --------------------------------------------------------------------------- #
# 5. Output uniqueness / nonce hygiene                                        #
# --------------------------------------------------------------------------- #


class TestUniqueness:
    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    def test_same_input_twice_gives_unrelated_containers(
        self, sample_file: Path, tmp_path: Path, owner_key: bytes, algorithm: str
    ) -> None:
        first = encrypt_file(sample_file, owner_key, tmp_path / "1.vault", algorithm=algorithm)
        second = encrypt_file(sample_file, owner_key, tmp_path / "2.vault", algorithm=algorithm)
        a, b = split_container(first.read_bytes()), split_container(second.read_bytes())

        assert a.wrap_nonce != b.wrap_nonce
        assert a.payload_nonce != b.payload_nonce
        assert a.wrapped_dek != b.wrapped_dek
        assert a.ciphertext != b.ciphertext
        assert a.tag != b.tag
        assert decrypt_bytes(first.read_bytes(), owner_key).plaintext == sample_file.read_bytes()
        assert decrypt_bytes(second.read_bytes(), owner_key).plaintext == sample_file.read_bytes()

    def test_nonces_and_wrapped_deks_never_repeat(self, owner_key: bytes) -> None:
        n = 300
        layouts = [split_container(encrypt_bytes(b"same", owner_key)) for _ in range(n)]
        wrap_nonces = {l.wrap_nonce for l in layouts}
        payload_nonces = {l.payload_nonce for l in layouts}
        wrapped_deks = {l.wrapped_dek for l in layouts}
        assert len(wrap_nonces) == n
        assert len(payload_nonces) == n
        assert len(wrapped_deks) == n
        assert wrap_nonces.isdisjoint(payload_nonces)

    def test_all_randomness_comes_from_os_urandom(
        self, owner_key: bytes, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        requested: list[int] = []
        real_urandom = os.urandom

        def spy(size: int) -> bytes:
            requested.append(size)
            return real_urandom(size)

        monkeypatch.setattr(symmetric.os, "urandom", spy)
        encrypt_bytes(b"x", owner_key)
        # DEK (32 B), wrap nonce (12 B), payload nonce (12 B) -- nothing else.
        assert requested == [KEY_LEN, NONCE_LEN, NONCE_LEN]

    def test_module_does_not_use_insecure_rng(self) -> None:
        tree = ast.parse(Path(symmetric.__file__).read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert "random" not in imported
        assert "numpy" not in imported


# --------------------------------------------------------------------------- #
# 6. Disk-failure handling                                                    #
# --------------------------------------------------------------------------- #


class TestDiskSafety:
    @pytest.mark.parametrize("failure", ["wrong_key", "flipped_ct", "flipped_header", "truncated", "garbage"])
    def test_failed_decryption_leaves_no_file(
        self, vault_file: Path, owner_key: bytes, out_dir: Path, tmp_path: Path, failure: str
    ) -> None:
        blob = vault_file.read_bytes()
        layout = split_container(blob)
        key = owner_key
        if failure == "wrong_key":
            key = generate_owner_key()
        elif failure == "flipped_ct":
            blob = flip_bit(blob, layout.ciphertext_start + 10)
        elif failure == "flipped_header":
            blob = flip_bit(blob, layout.header_start + 3)
        elif failure == "truncated":
            blob = blob[: len(blob) // 2]
        else:
            blob = os.urandom(len(blob))
        bad = tmp_path / "bad.vault"
        bad.write_bytes(blob)
        assert_decrypt_fails_cleanly(bad, key, out_dir / "restored.pdf")

    def test_existing_output_is_never_overwritten_on_decrypt(
        self, vault_file: Path, owner_key: bytes, out_dir: Path
    ) -> None:
        target = out_dir / "precious.pdf"
        target.write_bytes(b"pre-existing data")
        with pytest.raises(FileExistsError):
            decrypt_file(vault_file, owner_key, target)
        assert target.read_bytes() == b"pre-existing data"

    def test_existing_output_is_never_overwritten_on_encrypt(
        self, sample_file: Path, owner_key: bytes, out_dir: Path
    ) -> None:
        target = out_dir / "existing.vault"
        target.write_bytes(b"keep me")
        with pytest.raises(FileExistsError):
            encrypt_file(sample_file, owner_key, target)
        assert target.read_bytes() == b"keep me"

    def test_failed_decrypt_does_not_touch_existing_output(
        self, vault_file: Path, out_dir: Path
    ) -> None:
        target = out_dir / "precious.pdf"
        target.write_bytes(b"pre-existing data")
        with pytest.raises((FileExistsError, DecryptionFailedError)):
            decrypt_file(vault_file, generate_owner_key(), target)
        assert target.read_bytes() == b"pre-existing data"

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
    def test_symlink_output_is_refused(
        self, vault_file: Path, owner_key: bytes, out_dir: Path, tmp_path: Path
    ) -> None:
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"do not clobber")
        link = out_dir / "link.pdf"
        link.symlink_to(victim)
        with pytest.raises(FileExistsError):
            decrypt_file(vault_file, owner_key, link)
        assert victim.read_bytes() == b"do not clobber"

    def test_io_error_mid_write_removes_partial_output(
        self, vault_file: Path, owner_key: bytes, out_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def write_half_then_fail(fd: int, data: bytes) -> None:
            os.write(fd, data[: len(data) // 2])
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(symmetric, "_write_all", write_half_then_fail)
        target = out_dir / "restored.pdf"
        with pytest.raises(OSError) as info:
            decrypt_file(vault_file, owner_key, target)
        assert info.value.errno == errno.ENOSPC
        assert not target.exists()
        assert listing(out_dir) == set()

    def test_io_error_mid_write_on_encrypt_removes_partial_output(
        self, sample_file: Path, owner_key: bytes, out_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail(fd: int, data: bytes) -> None:
            os.write(fd, data[:10])
            raise OSError(errno.EIO, "I/O error")

        monkeypatch.setattr(symmetric, "_write_all", fail)
        with pytest.raises(OSError):
            encrypt_file(sample_file, owner_key, out_dir / "x.vault")
        assert listing(out_dir) == set()

    def test_missing_input_creates_nothing(self, owner_key: bytes, out_dir: Path, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            decrypt_file(tmp_path / "nope.vault", owner_key, out_dir / "x")
        with pytest.raises(FileNotFoundError):
            encrypt_file(tmp_path / "nope.txt", owner_key, out_dir / "y")
        assert listing(out_dir) == set()

    def test_oversized_input_is_rejected_before_writing(
        self, plain_dir: Path, owner_key: bytes, out_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(symmetric, "MAX_PLAINTEXT_SIZE", 10)
        big = plain_dir / "big.bin"
        big.write_bytes(b"x" * 11)
        with pytest.raises(PlaintextTooLargeError):
            encrypt_file(big, owner_key, out_dir / "big.vault")
        assert listing(out_dir) == set()


# --------------------------------------------------------------------------- #
# Error hygiene (no oracles) and input validation                             #
# --------------------------------------------------------------------------- #


class TestErrorHygiene:
    def test_all_failures_are_indistinguishable(self, owner_key: bytes) -> None:
        blob = encrypt_bytes(b"content", owner_key, metadata={"k": "v"})
        layout = split_container(blob)
        header = layout.header_json
        header["metadata"]["k"] = "w"
        variants = {
            "wrong_key": (blob, generate_owner_key()),
            "flipped_ciphertext": (flip_bit(blob, layout.ciphertext_start), owner_key),
            "flipped_tag": (flip_bit(blob, layout.tag_start), owner_key),
            "flipped_wrapped_dek": (flip_bit(blob, layout.wrapped_dek_start), owner_key),
            "tampered_metadata": (replace_header(blob, canonical(header)), owner_key),
            "bad_magic": (b"XXXX" + blob[4:], owner_key),
            "truncated": (blob[:20], owner_key),
            "not_json": (replace_header(blob, b"\xff\xfe"), owner_key),
        }
        observed = set()
        for name, (data, key) in variants.items():
            with pytest.raises(DecryptionFailedError) as info:
                decrypt_bytes(data, key)
            exc = info.value
            assert type(exc) is DecryptionFailedError, name
            assert exc.__cause__ is None and exc.__context__ is None, name
            observed.add((str(exc), exc.args))
        assert len(observed) == 1, "error messages must not reveal the failure stage"

    def test_exception_hierarchy(self) -> None:
        assert issubclass(DecryptionFailedError, VaultError)
        for cls in (InvalidKeyError, InvalidMetadataError, PlaintextTooLargeError, UnsupportedAlgorithmError):
            assert issubclass(cls, VaultError) and issubclass(cls, ValueError)


class TestInputValidation:
    @pytest.mark.parametrize(
        "metadata",
        [
            {"blob": b"bytes are not JSON"},
            {"obj": object()},
            {1: "non-string key"},
            {"tuple": (1, 2)},
            {"nan": float("nan")},
            {"inf": float("inf")},
        ],
        ids=["bytes", "object", "int_key", "tuple", "nan", "inf"],
    )
    def test_invalid_metadata_rejected_without_output(
        self, sample_file: Path, owner_key: bytes, out_dir: Path, metadata: dict
    ) -> None:
        with pytest.raises(InvalidMetadataError):
            encrypt_file(sample_file, owner_key, out_dir / "m.vault", metadata)
        assert listing(out_dir) == set()

    def test_non_mapping_metadata_rejected(self, owner_key: bytes) -> None:
        with pytest.raises(InvalidMetadataError):
            encrypt_bytes(b"x", owner_key, metadata=["not", "a", "dict"])  # type: ignore[arg-type]

    def test_circular_metadata_rejected(self, owner_key: bytes) -> None:
        loop: dict = {}
        loop["self"] = loop
        with pytest.raises(InvalidMetadataError):
            encrypt_bytes(b"x", owner_key, metadata=loop)

    def test_oversized_metadata_rejected(self, owner_key: bytes) -> None:
        with pytest.raises(InvalidMetadataError):
            encrypt_bytes(b"x", owner_key, metadata={"pad": "A" * (70 * 1024)})

    @pytest.mark.parametrize("algorithm", ["AES-128-GCM", "AES-256-CBC", "aes-256-gcm", "", None])
    def test_unsupported_algorithm_rejected(
        self, sample_file: Path, owner_key: bytes, out_dir: Path, algorithm: object
    ) -> None:
        with pytest.raises(UnsupportedAlgorithmError):
            encrypt_file(sample_file, owner_key, out_dir / "a.vault", algorithm=algorithm)  # type: ignore[arg-type]
        assert listing(out_dir) == set()

