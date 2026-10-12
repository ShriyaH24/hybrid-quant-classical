"""
crypto/key_verification.py

After Cascade, Alice and Bob confirm their keys are identical by
comparing a short tag computed with a fresh random nonce. The tag
reveals at most `tag_bits` bits, which privacy amplification removes.
"""

import hashlib
import hmac
from typing import Sequence

from crypto.privacy import bits_to_bytes


def verification_tag(bits: Sequence[int], nonce: bytes, tag_bits: int = 64) -> str:
    digest = hashlib.sha256(b"HCQC-verify|" + nonce + bits_to_bytes(bits)).digest()
    return digest[: tag_bits // 8].hex()


def tags_match(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
