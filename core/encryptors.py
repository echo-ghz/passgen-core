"""Argon2 + AES-GCM utilities (core)."""

from __future__ import annotations

import base64
from typing import Any, Dict, Tuple

from argon2 import PasswordHasher
from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Parameters — documenta che possono essere configurati in GUI
ARGON2_TIME = 2
ARGON2_MEMORY = 65536  # KiB = 64 MiB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12  # recommended for GCM

_password_hasher = PasswordHasher(
    time_cost=ARGON2_TIME,
    memory_cost=ARGON2_MEMORY,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=SALT_LEN,
)


def hash_password_argon2(password: str) -> str:
    """Returns Argon2 encoded hash (verify with verify_password_argon2)."""
    return _password_hasher.hash(password)


def verify_password_argon2(encoded_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(encoded_hash, password)
    except Exception:
        return False


def derive_key_from_password(
    password: str,
    salt: bytes | None = None,
    key_len: int = 32,
    time_cost: int = ARGON2_TIME,
    memory_cost: int = ARGON2_MEMORY,
    parallelism: int = ARGON2_PARALLELISM,
) -> Tuple[bytes, bytes]:
    """Derive a raw key with Argon2id (returns (key, salt))."""
    if salt is None:
        salt = get_random_bytes(SALT_LEN)
    key = hash_secret_raw(
        password.encode("utf-8"),
        salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=key_len,
        type=Type.ID,
    )
    return key, salt


def encrypt_aes_gcm(
    plaintext: bytes, key: bytes, nonce: bytes | None = None
) -> Dict[str, str]:
    """Encrypt bytes and return base64-encoded pieces."""
    if nonce is None:
        nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_aes_gcm(payload: Dict[str, str], key: bytes) -> bytes:
    """Given base64-encoded ciphertext/nonce/tag, decrypt and return bytes."""
    ct = base64.b64decode(payload["ciphertext"])
    nonce = base64.b64decode(payload["nonce"])
    tag = base64.b64decode(payload["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)


def encrypt_with_password(plaintext: str, password: str) -> Dict[str, Any]:
    """Convenience: derive key via Argon2 and encrypt.
    Returns dict with salt + cipher parts."""
    key, salt = derive_key_from_password(password)
    payload = encrypt_aes_gcm(plaintext.encode("utf-8"), key)
    payload["salt"] = base64.b64encode(salt).decode("ascii")
    payload["kdf"] = {
        "time": ARGON2_TIME,
        "memory": ARGON2_MEMORY,
        "parallelism": ARGON2_PARALLELISM,
    }
    return payload


def decrypt_with_password(payload: Dict[str, Any], password: str) -> str:
    """Rebuild key from payload['salt'] and decrypt."""
    salt = base64.b64decode(payload["salt"])
    key, _ = derive_key_from_password(password, salt=salt)
    b = decrypt_aes_gcm(payload, key)
    return b.decode("utf-8")
