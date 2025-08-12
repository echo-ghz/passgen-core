# PassGen – API Reference

This document provides a detailed reference for the **public API** of the `passgen_core` package.  
All functions are designed to be **safe defaults** and **easy to use** in any Python project.

---

## 📦 Module: `password_generator`

### `generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True, exclude_ambiguous=False) -> str`

Generate a secure password with configurable options.

**Parameters:**
- `length` *(int, default=16)* – total password length (must be ≥ 4).
- `use_upper` *(bool, default=True)* – include uppercase letters.
- `use_lower` *(bool, default=True)* – include lowercase letters.
- `use_digits` *(bool, default=True)* – include digits.
- `use_symbols` *(bool, default=True)* – include symbols.
- `exclude_ambiguous` *(bool, default=False)* – remove visually similar characters (`O`, `0`, `I`, `l`).

**Returns:**
- A randomly generated password string.

**Raises:**
- `ValueError` if `length` is less than 4 or no character sets are enabled.

**Example:**
```python
from passgen_core.password_generator import generate_password

pw = generate_password(length=20, use_symbols=True, exclude_ambiguous=True)
print(pw)
```

---

## 🔐 Module: ```encryptors```
```hash_password_argon2(password: str) -> str
```
Hash a password using Argon2id with secure default parameters.

Parameters:

    ```password``` (str) – the plaintext password.

Returns:

    Argon2id encoded hash string

---

```verify_password_argon2(encoded_hash: str, password: str) -> bool```

Verify a password against a stored Argon2id hash.

Parameters:

    ```encoded_hash``` (str) – Argon2id hash to verify against.

    ```password``` (str) – plaintext password to verify.

Returns:

    ```True``` if valid, ```False``` otherwise.

---

```derive_key_from_password(password: str, salt: bytes | None = None, key_len: int = 32, time_cost: int = ARGON2_TIME, memory_cost: int = ARGON2_MEMORY, parallelism: int = ARGON2_PARALLELISM) -> (bytes, bytes)```

Derive a raw encryption key from a password using Argon2id as KDF.

Parameters:

    ```password``` (str) – plaintext password.

    ```salt``` (bytes | None, default=None) – optional salt (randomly generated if ```None```).

    ```key_len``` (int, default=32) – desired key length in bytes.

    ```time_cost```, ```memory_cost```, ```parallelism``` – Argon2 parameters.

Returns:

    ```(key, salt)``` tuple.

---

```encrypt_aes_gcm(plaintext: bytes, key: bytes, nonce: bytes | None = None) -> dict
```
Encrypt data using AES-256 in GCM mode.

Parameters:

    ```plaintext``` (bytes) – data to encrypt.

    ```key``` (bytes) – encryption key.

    ```nonce``` (bytes | None, default=None) – optional nonce (random if ```None```).

Returns:

    Dictionary with base64-encoded ```"ciphertext"```, ```"nonce"```, ```"tag"```.

---

```decrypt_aes_gcm(payload: dict, key: bytes) -> bytes
```
Decrypt data previously encrypted with encrypt_aes_gcm.

Parameters:

    ```payload``` (dict) – contains ```"ciphertext"```, ```"nonce"```, ```"tag"```.

    ```key``` (bytes) – encryption key.

Returns:

    Decrypted plaintext bytes.

---


```encrypt_with_password(plaintext: str, password: str) -> dict
```
Convenience method: derive an AES key from a password and encrypt the plaintext.

Returns:

    Dictionary containing ```"salt"```, ```"ciphertext"```, ```"nonce"```, ```"tag"```, ```"kdf"```.

---

```decrypt_with_password(payload: dict, password: str) -> str
```
Convenience method: decrypt text encrypted with ```encrypt_with_password```.

Returns:

    Decrypted plaintext string.

---

## 📜 Notes

    Argon2id is chosen for password hashing and key derivation because it is memory-hard and resistant to GPU/ASIC cracking.

    AES-GCM is used for encryption because it provides confidentiality and integrity.

    Always store and handle salts, nonces, and tags securely — they are required for decryption.

    Changing Argon2 parameters will affect compatibility with previously generated keys or hashes.

