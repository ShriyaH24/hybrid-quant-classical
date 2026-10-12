"""
crypto/aes.py

AES-256-GCM. The associated data (AAD) binds each ciphertext to its
epoch, sequence number and gear, so a message can't be replayed into
another epoch or reordered without detection.
"""

import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_message(key: bytes, plaintext: str, aad: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return nonce, ciphertext


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes] = None) -> str:
    return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")
