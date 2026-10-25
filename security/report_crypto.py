#!/usr/bin/env python3
# HackPilot core module
"""AES-256-GCM encryption at rest for HackPilot report artifacts.

Guarded by REPORT_ENCRYPTION_KEY (.env, base64-encoded 32-byte key). If the
key is absent or malformed, every write falls back to plaintext and logs a
warning instead of breaking the report pipeline - the same graceful-
degradation pattern the rest of the project uses for optional dependencies
(see MODULES_AVAILABLE in advance_hackpilot.py).
"""

import base64
import logging
import os
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("hackpilot.report_crypto")

_NONCE_SIZE = 12
ENCRYPTED_SUFFIX = ".enc"


def _load_key() -> Optional[bytes]:
    raw = os.getenv("REPORT_ENCRYPTION_KEY", "")
    if not raw:
        return None
    try:
        key = base64.b64decode(raw)
    except Exception:
        logger.warning("REPORT_ENCRYPTION_KEY is not valid base64 - reports will be stored unencrypted")
        return None
    if len(key) != 32:
        logger.warning("REPORT_ENCRYPTION_KEY must decode to 32 bytes for AES-256 - reports will be stored unencrypted")
        return None
    return key


def encryption_enabled() -> bool:
    return _load_key() is not None


def encrypt_bytes(data: bytes) -> bytes:
    key = _load_key()
    if key is None:
        raise RuntimeError("REPORT_ENCRYPTION_KEY not configured")
    nonce = os.urandom(_NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt_bytes(blob: bytes) -> bytes:
    key = _load_key()
    if key is None:
        raise RuntimeError("REPORT_ENCRYPTION_KEY not configured")
    nonce, ciphertext = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def write_report_file(path: Union[str, Path], data: bytes) -> str:
    """Persist report bytes to disk, encrypted when a key is configured.

    Returns the path actually written: ``<path>.enc`` when encryption ran,
    ``<path>`` unchanged otherwise - callers hand that path to whatever
    reads the report back (e.g. read_report_file).
    """
    path = Path(path)
    key = _load_key()
    if key is None:
        logger.warning("REPORT_ENCRYPTION_KEY not set - writing %s unencrypted", path)
        path.write_bytes(data)
        return str(path)

    enc_path = Path(str(path) + ENCRYPTED_SUFFIX)
    enc_path.write_bytes(encrypt_bytes(data))
    return str(enc_path)


def write_report_text(path: Union[str, Path], text: str) -> str:
    return write_report_file(path, text.encode("utf-8"))


def read_report_file(path: Union[str, Path]) -> bytes:
    """Read a report back, transparently decrypting ``.enc`` files."""
    path = Path(path)
    if path.suffix == ENCRYPTED_SUFFIX:
        return decrypt_bytes(path.read_bytes())
    return path.read_bytes()
