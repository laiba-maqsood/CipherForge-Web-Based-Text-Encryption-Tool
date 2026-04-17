# 🔐 CipherForge  Web-Based Text Encryption Tool

A full-featured, single-page web application for encrypting, decrypting, and hashing text using **11 cryptographic algorithms** — from classical ciphers to modern AES/RSA.

##  Tech Stack
- **Frontend + Backend:** Python · Streamlit
- **Cryptography:** PyCryptodome + Python built-ins (`hashlib`, `secrets`)
- **No extra dependencies** for the 6 classical ciphers  pure Python

##  Features
- **11 encryption algorithms** across classical and modern categories
- **4 hash algorithms** (SHA-256, SHA-512, MD5, SHA-1)
- Full **encrypt + decrypt** support for all reversible algorithms
- User **authentication** with salted password hashing
- Personal **encrypted message vault** (save & label messages)
- One-click **copy** for all ciphertext and key outputs
- RSA **keypair generation** + PEM private key download
- Binary/hex view for Vernam cipher output
- Interactive **Algorithm Reference Guide** for all 11 ciphers

##  Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

Opens at: `http://localhost:8501`

##  Project Structure
```
crypto_tool/
├── app.py                # Main Streamlit application (UI + routing + pages)
├── encryption_engine.py  # All cryptographic functions (11 algorithms)
├── requirements.txt      # Python dependencies (unchanged)
├── README.md             # This file
├── REPORT.md             # Full technical report
└── users.json            # Auto-generated at runtime (user vault data)
```

##  All Algorithms

### Classical Ciphers (Pure Python  no extra libraries)
| Algorithm | Type | Key | Security |
|---|---|---|---|
| Caesar Cipher | Substitution | Shift 1–25 |  Very weak |
| Vigenère Cipher | Polyalphabetic substitution | Keyword |  Weak |
| Autokey Vigenère | Autokey substitution | Primer keyword |  Moderate |
| Vernam Cipher | XOR stream cipher | Same-length key (auto-gen) |  Strong if key is random |
| One-Time Pad (OTP) | Perfect secrecy XOR | Random same-length key |  Mathematically unbreakable |
| Columnar Transposition | Transposition | Keyword |  Weak alone |
| Rail Fence Cipher | Transposition | Number of rails |  Very weak |
| Base64 | Encoding | None |  Not encryption |

### Modern Ciphers (PyCryptodome)
| Algorithm | Type | Key Size | Security |
|---|---|---|---|
| AES-256-CBC | Symmetric block cipher | 256-bit |  Gold standard |
| DES-CBC | Symmetric block cipher | 64-bit |  Deprecated |
| RSA-2048 | Asymmetric public-key | 2048-bit pair |  Strong |

### Hash Functions (Python `hashlib`)
| Algorithm | Output | Status |
|---|---|---|
| SHA-256 | 256-bit |  Recommended |
| SHA-512 | 512-bit |  Recommended |
| MD5 | 128-bit |  Broken (use for checksums only) |
| SHA-1 | 160-bit |  Deprecated |

##  App Pages
1. ** Encrypt / Decrypt**  Main tool with full algorithm selector, key management, vault save
2. **#️ Hashing**  One-way cryptographic hashing with copy support
3. ** My Vault**  View and manage saved encrypted messages (requires login)
4. ** Algorithm Guide**  Interactive reference cards for all 11 algorithms

##  Dependencies
```
streamlit>=1.32.0
pycryptodome>=3.20.0
bcrypt>=4.1.0
```
> The 6 classical ciphers (Vigenère, Autokey Vigenère, Vernam, OTP, Columnar Transposition, Rail Fence) use **only Python standard library**  no extra packages needed.

