"""
encryption_engine.py
Core cryptographic functions for the Web-Based Text Encryption Tool.
Algorithms: Caesar Cipher, AES-256, DES, RSA, Base64, SHA-256, MD5, SHA-512
"""

import base64
import hashlib
import os
import json
import string
import secrets
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ─────────────────────────────────────────────
#  CAESAR CIPHER
# ─────────────────────────────────────────────
def caesar_encrypt(text: str, shift: int = 13) -> dict:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return {
        "ciphertext": "".join(result),
        "key": str(shift),
        "algorithm": "Caesar Cipher"
    }


def caesar_decrypt(ciphertext: str, shift: int = 13) -> str:
    return caesar_encrypt(ciphertext, -shift)["ciphertext"]


# ─────────────────────────────────────────────
#  BASE64
# ─────────────────────────────────────────────
def base64_encrypt(text: str) -> dict:
    encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
    return {
        "ciphertext": encoded,
        "key": "N/A (encoding)",
        "algorithm": "Base64"
    }


def base64_decrypt(ciphertext: str) -> str:
    return base64.b64decode(ciphertext.encode('utf-8')).decode('utf-8')


# ─────────────────────────────────────────────
#  AES-256 (CBC mode)
# ─────────────────────────────────────────────
def aes_encrypt(text: str, key: bytes = None) -> dict:
    if key is None:
        key = get_random_bytes(32)          # 256-bit key
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(text.encode('utf-8'), AES.block_size)
    ciphertext_bytes = cipher.encrypt(padded)
    payload = base64.b64encode(iv + ciphertext_bytes).decode('utf-8')
    return {
        "ciphertext": payload,
        "key": base64.b64encode(key).decode('utf-8'),
        "algorithm": "AES-256-CBC"
    }


def aes_decrypt(ciphertext_b64: str, key_b64: str) -> str:
    key = base64.b64decode(key_b64)
    data = base64.b64decode(ciphertext_b64)
    iv, ciphertext_bytes = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext_bytes), AES.block_size).decode('utf-8')


# ─────────────────────────────────────────────
#  DES (CBC mode)
# ─────────────────────────────────────────────
def des_encrypt(text: str, key: bytes = None) -> dict:
    if key is None:
        key = get_random_bytes(8)           # 64-bit key (DES requirement)
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pad(text.encode('utf-8'), DES.block_size)
    ciphertext_bytes = cipher.encrypt(padded)
    payload = base64.b64encode(iv + ciphertext_bytes).decode('utf-8')
    return {
        "ciphertext": payload,
        "key": base64.b64encode(key).decode('utf-8'),
        "algorithm": "DES-CBC"
    }


def des_decrypt(ciphertext_b64: str, key_b64: str) -> str:
    key = base64.b64decode(key_b64)
    data = base64.b64decode(ciphertext_b64)
    iv, ciphertext_bytes = data[:8], data[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext_bytes), DES.block_size).decode('utf-8')


# ─────────────────────────────────────────────
#  RSA (2048-bit, OAEP padding)
# ─────────────────────────────────────────────
def rsa_generate_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key


def rsa_encrypt(text: str, public_key_pem: str) -> dict:
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key)
    # RSA can only encrypt small payloads; chunk if needed
    max_chunk = 190
    chunks = [text.encode('utf-8')[i:i+max_chunk]
              for i in range(0, len(text.encode('utf-8')), max_chunk)]
    encrypted_chunks = [cipher.encrypt(chunk) for chunk in chunks]
    payload = base64.b64encode(b"||".join(encrypted_chunks)).decode('utf-8')
    return {
        "ciphertext": payload,
        "key": public_key_pem,
        "algorithm": "RSA-2048-OAEP"
    }


def rsa_decrypt(ciphertext_b64: str, private_key_pem: str) -> str:
    priv_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(priv_key)
    data = base64.b64decode(ciphertext_b64)
    chunks = data.split(b"||")
    decrypted = b"".join(cipher.decrypt(chunk) for chunk in chunks)
    return decrypted.decode('utf-8')


# ─────────────────────────────────────────────
#  VIGENÈRE CIPHER
# ─────────────────────────────────────────────
def _vigenere_core(text: str, key: str, mode: str) -> str:
    """Shared engine for Vigenère encrypt/decrypt. mode='E' or 'D'."""
    key = key.upper()
    result = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(key[key_idx % len(key)]) - ord('A')
            shift = k if mode == 'E' else -k
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_encrypt(text: str, key: str) -> dict:
    if not key.isalpha():
        raise ValueError("Vigenère key must contain letters only.")
    return {
        "ciphertext": _vigenere_core(text, key, 'E'),
        "key": key.upper(),
        "algorithm": "Vigenère Cipher"
    }


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    if not key.isalpha():
        raise ValueError("Vigenère key must contain letters only.")
    return _vigenere_core(ciphertext, key, 'D')


# ─────────────────────────────────────────────
#  AUTOKEY VIGENÈRE CIPHER
# ─────────────────────────────────────────────
def autokey_vigenere_encrypt(text: str, key: str) -> dict:
    """Key is primed with the provided keyword, then extended using plaintext itself."""
    if not key.isalpha():
        raise ValueError("Autokey key must contain letters only.")
    letters = [ch for ch in text if ch.isalpha()]
    full_key = (key + "".join(letters)).upper()
    result = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(full_key[key_idx]) - ord('A')
            result.append(chr((ord(ch) - base + k) % 26 + base))
            key_idx += 1
        else:
            result.append(ch)
    return {
        "ciphertext": "".join(result),
        "key": key.upper(),
        "algorithm": "Autokey Vigenère Cipher"
    }


def autokey_vigenere_decrypt(ciphertext: str, key: str) -> str:
    if not key.isalpha():
        raise ValueError("Autokey key must contain letters only.")
    key = key.upper()
    result = []
    recovered_key = list(key)
    key_idx = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            k = ord(recovered_key[key_idx]) - ord('A')
            plain_ch = chr((ord(ch) - base - k) % 26 + base)
            result.append(plain_ch)
            recovered_key.append(plain_ch.upper())
            key_idx += 1
        else:
            result.append(ch)
    return "".join(result)


# ─────────────────────────────────────────────
#  VERNAM CIPHER  (XOR stream cipher)
#
#  Operates only on alphabetic characters; non-letter chars are
#  preserved in-place. XOR on letter indices (0-25) can yield
#  0-31 (5 bits). We encode the result as two uppercase letters
#  (base-26 pair AA-FA range is avoided; instead just store as
#  one char from extended set). To avoid collisions with
#  passthrough digits, we output the ciphertext as UPPERCASE
#  letters for XOR 0-25, and symbols [,],^,_,`,{ for 26-31.
#  Non-letter plaintext chars are wrapped in curly braces.
#  → ciphertext is always human-readable text (no hex).
# ─────────────────────────────────────────────
# 32-char encoding: A-Z for 0-25, then !@#$%& for 26-31
_V32_ENC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%&"


def vernam_encrypt(text: str, key: str = "") -> dict:
    """
    Vernam XOR on letter indices (0–25).
    Non-letter chars preserved. Ciphertext is always readable text.
    Manual key supported (letters only, length ≥ number of letters in text).
    """
    letters_in_text = [ch for ch in text if ch.isalpha()]
    n = len(letters_in_text)

    if not key:
        key = "".join(chr(secrets.randbelow(26) + ord('A')) for _ in range(n))
    else:
        key = key.upper()
        if not key.isalpha():
            raise ValueError("Vernam key must contain letters only (A-Z).")
        if len(key) < n:
            raise ValueError(
                f"Key must be at least {n} letters long "
                f"(one per letter in plaintext)."
            )

    result = []
    key_idx = 0
    for ch in text:
        if ch.isalpha():
            p = ord(ch.upper()) - ord('A')    # 0-25
            k = ord(key[key_idx]) - ord('A')  # 0-25
            result.append(_V32_ENC[p ^ k])    # 0-31 → printable char
            key_idx += 1
        else:
            # Wrap non-letter chars so decrypt can distinguish them
            result.append(f"[{ch}]")

    return {
        "ciphertext": "".join(result),
        "key": key[:n],
        "algorithm": "Vernam Cipher"
    }


def vernam_decrypt(ciphertext: str, key: str) -> str:
    """Vernam is self-inverse: apply same XOR to recover plaintext."""
    key = key.upper()
    if not key.isalpha():
        raise ValueError("Vernam key must contain letters only (A-Z).")

    result = []
    key_idx = 0
    i = 0
    while i < len(ciphertext):
        ch = ciphertext[i]
        if ch == '[':
            # Non-letter passthrough wrapped in [X]
            close = ciphertext.index(']', i)
            result.append(ciphertext[i+1:close])
            i = close + 1
        elif ch in _V32_ENC:
            if key_idx >= len(key):
                raise ValueError("Key is shorter than the ciphertext letter count.")
            c = _V32_ENC.index(ch)            # 0-31
            k = ord(key[key_idx]) - ord('A')  # 0-25
            p = c ^ k                         # recover letter index
            if p > 25:
                raise ValueError(
                    f"Decryption produced invalid letter index {p}. "
                    "Check that you are using the correct key."
                )
            result.append(chr(p + ord('A')))
            key_idx += 1
            i += 1
        else:
            result.append(ch)
            i += 1
    return "".join(result)


# ─────────────────────────────────────────────
#  ONE-TIME PAD (OTP)
# ─────────────────────────────────────────────
def otp_encrypt(text: str) -> dict:
    """
    True OTP: perfectly random key, same length as plaintext.
    Theoretically unbreakable when key is truly random and used only once.
    """
    key_bytes = secrets.token_bytes(len(text))
    text_bytes = text.encode('utf-8')
    cipher_bytes = bytes(a ^ b for a, b in zip(text_bytes, key_bytes))
    return {
        "ciphertext": base64.b64encode(cipher_bytes).decode('utf-8'),
        "key": base64.b64encode(key_bytes).decode('utf-8'),
        "algorithm": "One-Time Pad (OTP)"
    }


def otp_decrypt(ciphertext_b64: str, key_b64: str) -> str:
    cipher_bytes = base64.b64decode(ciphertext_b64)
    key_bytes = base64.b64decode(key_b64)
    if len(key_bytes) < len(cipher_bytes):
        raise ValueError("OTP key must be at least as long as the ciphertext.")
    plain_bytes = bytes(a ^ b for a, b in zip(cipher_bytes, key_bytes))
    return plain_bytes.decode('utf-8')


# ─────────────────────────────────────────────
#  COLUMNAR TRANSPOSITION CIPHER
# ─────────────────────────────────────────────
def _col_order(key: str) -> list:
    """Return column read-order based on alphabetical rank of key letters."""
    indexed = sorted(enumerate(key.upper()), key=lambda x: x[1])
    order = [0] * len(key)
    for rank, (orig_idx, _) in enumerate(indexed):
        order[orig_idx] = rank
    return order


def transposition_encrypt(text: str, key: str) -> dict:
    if not key.isalpha():
        raise ValueError("Transposition key must contain letters only.")
    cols = len(key)
    # Pad text with 'X' to fill the grid
    padded = text.replace(" ", "").upper()
    while len(padded) % cols != 0:
        padded += 'X'
    rows = len(padded) // cols
    grid = [list(padded[r * cols:(r + 1) * cols]) for r in range(rows)]
    order = _col_order(key)
    # Read columns in alphabetical key order
    col_map = [0] * cols
    for orig, rank in enumerate(order):
        col_map[rank] = orig
    ciphertext = ""
    for rank in range(cols):
        orig_col = col_map[rank]
        ciphertext += "".join(grid[r][orig_col] for r in range(rows))
    return {
        "ciphertext": ciphertext,
        "key": key.upper(),
        "algorithm": "Columnar Transposition Cipher"
    }


def transposition_decrypt(ciphertext: str, key: str) -> str:
    if not key.isalpha():
        raise ValueError("Transposition key must contain letters only.")
    cols = len(key)
    rows = len(ciphertext) // cols
    order = _col_order(key)
    col_map = [0] * cols
    for orig, rank in enumerate(order):
        col_map[rank] = orig
    # Split ciphertext back into columns
    columns = {}
    idx = 0
    for rank in range(cols):
        orig_col = col_map[rank]
        columns[orig_col] = list(ciphertext[idx:idx + rows])
        idx += rows
    # Reconstruct grid row by row
    plaintext = ""
    for r in range(rows):
        for c in range(cols):
            plaintext += columns[c][r]
    return plaintext.rstrip('X')


# ─────────────────────────────────────────────
#  RAIL FENCE CIPHER
# ─────────────────────────────────────────────
def rail_fence_encrypt(text: str, rails: int = 3) -> dict:
    if rails < 2:
        raise ValueError("Rail Fence requires at least 2 rails.")
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        fence[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    ciphertext = "".join("".join(row) for row in fence)
    return {
        "ciphertext": ciphertext,
        "key": str(rails),
        "algorithm": "Rail Fence Cipher"
    }


def rail_fence_decrypt(ciphertext: str, rails: int = 3) -> str:
    if rails < 2:
        raise ValueError("Rail Fence requires at least 2 rails.")
    n = len(ciphertext)
    # Determine which rail each position belongs to
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    # Count characters per rail
    counts = [pattern.count(r) for r in range(rails)]
    # Slice ciphertext into rails
    fence = []
    idx = 0
    for count in counts:
        fence.append(list(ciphertext[idx:idx + count]))
        idx += count
    # Read off in zigzag order
    pointers = [0] * rails
    result = []
    for r in pattern:
        result.append(fence[r][pointers[r]])
        pointers[r] += 1
    return "".join(result)


# ─────────────────────────────────────────────
#  HASHING
# ─────────────────────────────────────────────
def hash_text(text: str, algorithm: str) -> dict:
    algos = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "MD5":     hashlib.md5,
        "SHA-1":   hashlib.sha1,
    }
    if algorithm not in algos:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    digest = algos[algorithm](text.encode('utf-8')).hexdigest()
    return {
        "hash": digest,
        "algorithm": algorithm,
        "note": "Hashing is one-way and cannot be reversed."
    }


# ─────────────────────────────────────────────
#  SIMPLE USER STORE  (bonus auth feature)
# ─────────────────────────────────────────────
# Always store users.json next to this script, works on Windows/Mac/Linux
USER_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")


def _load_users() -> dict:
    if not os.path.exists(USER_DB_PATH):
        return {}
    with open(USER_DB_PATH) as f:
        return json.load(f)


def _save_users(users: dict):
    with open(USER_DB_PATH, "w") as f:
        json.dump(users, f, indent=2)


def register_user(username: str, password: str) -> bool:
    users = _load_users()
    if username in users:
        return False
    salt = os.urandom(16).hex()
    pw_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    users[username] = {"hash": pw_hash, "salt": salt, "messages": []}
    _save_users(users)
    return True


def login_user(username: str, password: str) -> bool:
    users = _load_users()
    if username not in users:
        return False
    stored = users[username]
    pw_hash = hashlib.sha256((password + stored["salt"]).encode()).hexdigest()
    return pw_hash == stored["hash"]


def save_message(username: str, label: str, algo: str, ciphertext: str, key: str = ""):
    users = _load_users()
    if username not in users:
        return
    users[username]["messages"].append({
        "label": label,
        "algorithm": algo,
        "ciphertext": ciphertext,
        "key": key
    })
    _save_users(users)


def get_messages(username: str) -> list:
    users = _load_users()
    return users.get(username, {}).get("messages", [])
