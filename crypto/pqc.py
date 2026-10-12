"""
crypto/pqc.py

Post-quantum primitives (NIST FIPS 203 / FIPS 204) from the
`cryptography` package (version 50 or newer):

  * ML-KEM-768  - key encapsulation (Gears 2 and 3)
  * ML-DSA-65   - signatures / authentication (Gears 2 and 3)

If the library or algorithms are missing, PQC_AVAILABLE is False and
the node can only offer Gear 1.
"""

from typing import Tuple

KEM_NAME = "ML-KEM-768"
SIG_NAME = "ML-DSA-65"

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

    mlkem.MLKEM768PrivateKey.generate()      # self-test: backend really supports it
    mldsa.MLDSA65PrivateKey.generate()
    PQC_AVAILABLE = True
    PQC_ERROR = ""
except Exception as exc:                      # ImportError, UnsupportedAlgorithm, ...
    PQC_AVAILABLE = False
    PQC_ERROR = f"{type(exc).__name__}: {exc}"


def _require():
    if not PQC_AVAILABLE:
        raise RuntimeError(f"Post-quantum crypto unavailable ({PQC_ERROR})")


# ---------------- ML-KEM-768 ----------------

def kem_keypair():
    """Returns (private_key_object, public_key_bytes)."""
    _require()
    sk = mlkem.MLKEM768PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


def kem_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Returns (shared_secret, ciphertext)."""
    _require()
    shared, ciphertext = mlkem.MLKEM768PublicKey.from_public_bytes(public_key).encapsulate()
    return shared, ciphertext


def kem_decapsulate(private_key, ciphertext: bytes) -> bytes:
    _require()
    return private_key.decapsulate(ciphertext)


# ---------------- ML-DSA-65 ----------------

def sig_keypair() -> Tuple[bytes, bytes]:
    """Returns (32-byte private seed, public key bytes)."""
    _require()
    sk = mldsa.MLDSA65PrivateKey.generate()
    return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()


def sig_sign(private_seed: bytes, message: bytes) -> bytes:
    _require()
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(private_seed).sign(message)


def sig_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    _require()
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except InvalidSignature:
        return False
