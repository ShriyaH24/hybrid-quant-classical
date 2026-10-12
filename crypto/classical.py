"""
crypto/classical.py

Classical primitives:
  * X25519 ECDH         - key exchange for Gear 1
  * Ed25519             - signatures when post-quantum is unavailable
  * HKDF-SHA256         - turns combined secrets into the AES-256 key

Gear 1 is NOT quantum-safe (Shor's algorithm breaks X25519/Ed25519).
It exists so the link degrades instead of failing, and every Gear 1
epoch is logged as a documented quantum risk.
"""

import hashlib
import hmac
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------- X25519 ----------------

def x25519_keypair() -> Tuple[X25519PrivateKey, bytes]:
    sk = X25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


def x25519_shared(sk: X25519PrivateKey, peer_public: bytes) -> bytes:
    return sk.exchange(X25519PublicKey.from_public_bytes(peer_public))


# ---------------- Ed25519 ----------------

def ed25519_keypair() -> Tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()


def ed25519_sign(private_raw: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(private_raw).sign(message)


def ed25519_verify(public_raw: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ---------------- HKDF ----------------

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


# ---------------- HMAC (key confirmation) ----------------

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_verify(key: bytes, message: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(hmac_sha256(key, message), tag)
