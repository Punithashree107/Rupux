"""
Core logic for the Secure File Share System tool.

Lets a user encrypt a file with a password before sharing it (email,
USB, cloud upload, etc.), and decrypt it again on the receiving end.

Uses Fernet (from the `cryptography` library) for authenticated
encryption -- AES-128-CBC for confidentiality plus HMAC-SHA256 for
integrity, so any tampering or corruption is detected on decrypt
rather than silently producing garbage. The key is derived from the
user's password via PBKDF2-HMAC-SHA256 with a random per-file salt
and a modern OWASP-recommended iteration count, so the same password
never produces the same key twice.

File format written by encrypt_file():
  [4 bytes magic "RPX1"] [16 bytes salt] [Fernet token bytes...]
"""
import base64
import os
import secrets
import string
from dataclasses import dataclass
from typing import Optional

MAGIC = b"RPX1"
SALT_LEN = 16
PBKDF2_ITERATIONS = 600_000  # OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256


@dataclass
class OperationResult:
    success: bool
    output_path: Optional[str] = None
    message: str = ""


def _derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def encrypt_file(input_path: str, output_path: str, password: str) -> OperationResult:
    from cryptography.fernet import Fernet

    if not password:
        return OperationResult(False, message="Password cannot be empty.")

    try:
        with open(input_path, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        return OperationResult(False, message=f"Could not read input file: {e}")

    salt = secrets.token_bytes(SALT_LEN)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(plaintext)

    try:
        with open(output_path, "wb") as f:
            f.write(MAGIC)
            f.write(salt)
            f.write(token)
    except Exception as e:
        return OperationResult(False, message=f"Could not write output file: {e}")

    return OperationResult(True, output_path=output_path, message="File encrypted successfully.")


def decrypt_file(input_path: str, output_path: str, password: str) -> OperationResult:
    from cryptography.fernet import Fernet, InvalidToken

    if not password:
        return OperationResult(False, message="Password cannot be empty.")

    try:
        with open(input_path, "rb") as f:
            raw = f.read()
    except Exception as e:
        return OperationResult(False, message=f"Could not read input file: {e}")

    if len(raw) < len(MAGIC) + SALT_LEN or not raw.startswith(MAGIC):
        return OperationResult(False, message="This doesn't look like a Rupux-encrypted file.")

    salt = raw[len(MAGIC):len(MAGIC) + SALT_LEN]
    token = raw[len(MAGIC) + SALT_LEN:]

    key = _derive_key(password, salt)
    try:
        plaintext = Fernet(key).decrypt(token)
    except InvalidToken:
        return OperationResult(
            False,
            message="Decryption failed — wrong password, or the file has been "
                    "corrupted/tampered with (integrity check failed).",
        )
    except Exception as e:
        return OperationResult(False, message=f"Decryption failed: {e}")

    try:
        with open(output_path, "wb") as f:
            f.write(plaintext)
    except Exception as e:
        return OperationResult(False, message=f"Could not write decrypted output: {e}")

    return OperationResult(True, output_path=output_path, message="File decrypted successfully.")


def generate_strong_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))
