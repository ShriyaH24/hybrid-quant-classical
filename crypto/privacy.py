"""
crypto/privacy.py

Privacy amplification with a random Toeplitz matrix (a 2-universal
hash family), plus the bound that decides how many secret bits
survive.

Secret key length (asymptotic Shor-Preskill form with a simple
finite-size correction):

    l = n * (1 - h(e_up)) - leak_EC - verify_bits - 2*log2(1/eps)

    n        bits left after sifting and sampling
    e_up     QBER estimate + `sigmas` standard deviations
    h(.)     binary entropy (what Eve may know from the quantum channel)
    leak_EC  parity bits revealed by Cascade
    eps      security parameter

NOTE: the statistical correction is a normal approximation, which is
fine for a teaching demo but not a rigorous finite-key proof.
"""

import math
import os
from typing import List, Sequence, Tuple

import numpy as np


def binary_entropy(p: float) -> float:
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def qber_upper_bound(qber: float, n_sample: int, sigmas: float) -> float:
    """Pessimistic QBER: the sample estimate plus `sigmas` standard deviations."""
    p = max(qber, 1.0 / max(n_sample, 1))
    return min(0.5, qber + sigmas * math.sqrt(p * (1 - p) / max(n_sample, 1)))


def secret_key_length(n_key: int,
                      qber: float,
                      n_sample: int,
                      leaked_ec: int,
                      verify_bits: int,
                      eps: float,
                      sigmas: float) -> Tuple[int, float]:
    """Returns (secret_bits, qber_upper_bound)."""
    e_up = qber_upper_bound(qber, n_sample, sigmas)
    length = (n_key * (1 - binary_entropy(e_up))
              - leaked_ec - verify_bits - 2 * math.log2(1 / eps))
    # whole bytes only, so the key is used exactly as distilled (no padding bits)
    return max(0, int(math.floor(length)) // 8 * 8), e_up


def toeplitz_seed_bytes(n: int, out_len: int) -> int:
    """Number of bytes needed for a fully random out_len x n Toeplitz matrix."""
    return (n + out_len - 1 + 7) // 8


def new_toeplitz_seed(n: int, out_len: int) -> bytes:
    """
    n + out_len - 1 TRULY random bits (OS CSPRNG) - one per diagonal.
    The leftover hash lemma needs the matrix drawn uniformly from the whole
    Toeplitz family; stretching a short seed with a PRNG would not give that.
    The seed is public (sent in the clear and covered by the signed transcript).
    """
    return os.urandom(toeplitz_seed_bytes(n, out_len))


def toeplitz_hash(bits: Sequence[int], out_len: int, seed: bytes) -> List[int]:
    """
    y = T x over GF(2), where T is the out_len x n Toeplitz matrix whose
    n + out_len - 1 diagonals are the first bits of `seed`:
        T[i][j] = d[i - j + n - 1]
    """
    n = len(bits)
    if out_len <= 0 or n == 0:
        return []
    if out_len > n:
        raise ValueError("privacy amplification cannot output more bits than it gets")
    if len(seed) != toeplitz_seed_bytes(n, out_len):
        raise ValueError(f"Toeplitz seed must be {toeplitz_seed_bytes(n, out_len)} bytes, got {len(seed)}")
    diag = np.unpackbits(np.frombuffer(seed, dtype=np.uint8))[: n + out_len - 1].astype(np.int64)
    idx = np.arange(out_len)[:, None] - np.arange(n)[None, :] + (n - 1)
    x = np.asarray(bits, dtype=np.int64)
    return ((diag[idx] @ x) % 2).astype(int).tolist()


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    """Pack bits (MSB first); pads the last byte with zeros."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = list(bits[i:i + 8]) + [0] * (8 - len(bits[i:i + 8]))
        value = 0
        for b in chunk:
            value = (value << 1) | b
        out.append(value)
    return bytes(out)
