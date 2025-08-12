# PassGen

**PassGen Core** is the open-source foundation of the [PassGen](https://example.com) project — a secure and flexible password generation and encryption toolkit.

It provides **high-quality cryptographic primitives** and **safe password generation utilities** that can be integrated into any Python project.  
The core library is designed to be **generic, well-documented, and reusable**, without including any proprietary orchestration logic from the commercial GUI version.

---

## ✨ Features

- **Secure password generation**  
  - Configurable length  
  - Selectable character sets (uppercase, lowercase, digits, symbols)  
  - Option to exclude ambiguous characters

- **Modern password hashing**  
  - Argon2id (via `argon2-cffi`) with secure default parameters  
  - Easy verification API

- **Strong encryption**  
  - AES-256 in GCM mode (via `pycryptodome`)  
  - Password-based encryption using Argon2 as the KDF

- **Minimal, documented API**  
  - Simple to integrate into any application  
  - Clean separation of concerns

---

## 📦 Installation

From PyPI (when published):

```bash
pip install passgen-core
```

From source (development mode):

```bash
git clone https://github.com/YOURUSER/passgen-core.git
cd passgen-core
pip install -e .
```

---

## 🔍 Quick Example

```bash
from passgen_core import password_generator, encryptors

# Generate a secure password
pw = password_generator.generate_password(length=20, use_symbols=True)
print("Generated password:", pw)

# Hash it with Argon2id
hash_ = encryptors.hash_password_argon2(pw)
print("Argon2 hash:", hash_)

# Encrypt some data with a password
payload = encryptors.encrypt_with_password("super secret", "my master password")
print("Encrypted payload:", payload)

# Decrypt it
plaintext = encryptors.decrypt_with_password(payload, "my master password")
print("Decrypted:", plaintext)
```

---

## 📂 Project Structure

```bash
passgen-core/
│
├── passgen_core/           # Core library modules
│   ├── password_generator.py
│   ├── encryptors.py
│   └── __init__.py
├── examples/               # Minimal usage examples
├── tests/                  # Basic unit tests
└── docs/                   # Public documentation
```

---

## ⚖️ License

This repository is released under the MIT License.
You are free to use and modify the core library in your projects.
The commercial PassGen GUI application is closed-source and contains advanced orchestration, licensing, and proprietary features that are not part of this repository.

## 📢 Contributing

Pull requests for bug fixes and improvements are welcome!
For major changes, please open an issue first to discuss what you would like to change.

## 🔒 Security Notice

While passgen-core provides secure primitives, security also depends on correct usage.
Always follow best practices for key management, avoid weak passwords, and keep your dependencies up to date.

If you discover a security vulnerability, please do not open a public issue.
Instead, contact the maintainer directly at [echo.ghz@proton.me](mailto:echo.ghz@proton.me).

## 📜 Disclaimer

This project is provided as-is, without any warranty.
Use at your own risk.
The authors are not responsible for misuse of the library in insecure or illegal contexts.