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
    return max(0, int(math.floor(length))), e_up


def toeplitz_hash(bits: Sequence[int], out_len: int, seed: int) -> List[int]:
    """
    Multiply the key (as a GF(2) vector) by an out_len x n Toeplitz
    matrix generated from a public random seed.
    """
    n = len(bits)
    if out_len <= 0 or n == 0:
        return []
    diag = np.random.default_rng(seed).integers(0, 2, n + out_len - 1, dtype=np.int64)
    idx = np.arange(out_len)[:, None] - np.arange(n)[None, :] + (n - 1)
    matrix = diag[idx]
    x = np.asarray(bits, dtype=np.int64)
    return ((matrix @ x) % 2).astype(int).tolist()


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
