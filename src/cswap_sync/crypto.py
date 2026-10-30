"""Authenticated encryption of what a machine publishes (AES-256-GCM).

Every machine holds the same 32-byte sync key. The store only ever sees
ciphertext, so the store's access token alone exposes no login, and a blob
that was altered, or moved under another machine's name, fails to open.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CSS1"
NONCE_LEN = 12
KEY_LEN = 32


class DecryptError(Exception):
    pass


def new_key() -> str:
    return base64.b64encode(os.urandom(KEY_LEN)).decode()


def load_key(text: str) -> bytes:
    try:
        key = base64.b64decode(text.strip(), validate=True)
    except ValueError:
        raise ValueError("sync key is not valid base64") from None
    if len(key) != KEY_LEN:
        raise ValueError(f"sync key must decode to {KEY_LEN} bytes")
    return key


def _aad(machine: str) -> bytes:
    # Binds a blob to the machine that published it.
    return b"cswap-sync/v1:" + machine.encode()


def seal(key: bytes, machine: str, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plaintext, _aad(machine))


def unseal(key: bytes, machine: str, blob: bytes) -> bytes:
    head = len(MAGIC) + NONCE_LEN
    if not blob.startswith(MAGIC) or len(blob) < head + 16:
        raise DecryptError(f"{machine}: not a cswap-sync blob")
    try:
        return AESGCM(key).decrypt(blob[len(MAGIC):head], blob[head:], _aad(machine))
    except InvalidTag:
        raise DecryptError(f"{machine}: wrong sync key or altered data") from None
