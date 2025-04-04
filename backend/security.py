import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Persistent AES Key Storage
KEY_FILE = "aes_key.txt"

def load_or_generate_key():
    """
    Loads the AES key from a file or generates a new one if it doesn't exist.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = os.urandom(32)  # AES-256 requires a 32-byte key
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

SECRET_KEY = load_or_generate_key()

def encrypt_password(password: str) -> str:
    """
    Encrypts a password using AES-256 in CBC mode.
    Returns a base64-encoded string.
    """
    iv = os.urandom(16)  # Generate a random IV
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Store IV + encrypted data in base64 format
    encrypted_data = base64.b64encode(iv + encrypted).decode("utf-8")
    return encrypted_data

def decrypt_password(encrypted_password: str) -> str:
    """
    Decrypts a password encrypted using AES-256 in CBC mode.
    Takes a base64-encoded string and returns the original password.
    """
    encrypted_data = base64.b64decode(encrypted_password)  # Decode from base64

    iv = encrypted_data[:16]  # Extract IV
    encrypted = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_password = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_password.decode("utf-8")  # Decode bytes to string
