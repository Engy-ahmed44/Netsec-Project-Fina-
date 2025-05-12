import os
import json
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

KEY_FILE = Path("GLOBAL_KEY.bin")
ACCESS_FILE = Path("access_requests.json")

def _load_or_create_key() -> bytes:
    if not KEY_FILE.exists():
        key = AESGCM.generate_key(bit_length=128)
        KEY_FILE.write_bytes(key)
        return key
    return KEY_FILE.read_bytes()

def encrypt_file(data: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(_load_or_create_key())
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce, ct

def decrypt_file(nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(_load_or_create_key())
    return aesgcm.decrypt(nonce, ciphertext, None)

def hash_password(password: str) -> dict:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return {"salt": salt.hex(), "hash": key.hex()}

def verify_password(stored: dict, password: str) -> bool:
    salt = bytes.fromhex(stored["salt"])
    key  = bytes.fromhex(stored["hash"])
    kdf  = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), key)
        return True
    except:
        return False

def load_access_requests() -> dict:
    try:
        with ACCESS_FILE.open("r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to read access_requests.json: {e}")
        return {"request": {}, "grant": {}, "private": {}}


def save_access_requests(data: dict) -> None:
    try:
        with ACCESS_FILE.open("w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[ERROR] Failed to write access_requests.json: {e}")
