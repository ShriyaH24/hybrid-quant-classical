"""
crypto/bb84.py

Classical bookkeeping for BB84: random bits/bases, sifting,
QBER sampling.

Bases are encoded as integers:
    0 = Z / rectilinear  ("+")
    1 = X / diagonal     ("x")

All randomness comes from the `secrets` module (a CSPRNG).
"""

import secrets
from typing import List, Sequence, Tuple

BASIS_SYMBOL = {0: "+", 1: "x"}


def random_bits(n: int) -> List[int]:
    return [secrets.randbits(1) for _ in range(n)]


def random_bases(n: int) -> List[int]:
    return [secrets.randbits(1) for _ in range(n)]


def matching_indices(alice_bases: Sequence[int], bob_bases: Sequence[int]) -> List[int]:
    """Positions where Alice and Bob happened to use the same basis."""
    return [i for i, (a, b) in enumerate(zip(alice_bases, bob_bases)) if a == b]


def select(bits: Sequence[int], indices: Sequence[int]) -> List[int]:
    return [bits[i] for i in indices]


def choose_sample(n: int, fraction: float) -> List[int]:
    """
    Random subset of sifted positions that will be revealed publicly
    to estimate the QBER. These bits are discarded afterwards.
    """
    k = max(1, min(n, int(round(n * fraction))))
    return sorted(secrets.SystemRandom().sample(range(n), k))


def remove_indices(bits: Sequence[int], indices: Sequence[int]) -> List[int]:
    drop = set(indices)
    return [b for i, b in enumerate(bits) if i not in drop]


def calculate_qber(a: Sequence[int], b: Sequence[int]) -> float:
    if not a:
        return 1.0
    return sum(x != y for x, y in zip(a, b)) / len(a)


def sift_and_sample(bits: Sequence[int],
                    alice_bases: Sequence[int],
                    bob_bases: Sequence[int],
                    sample_idx: Sequence[int]) -> Tuple[List[int], List[int]]:
    """
    Returns (sample_bits, remaining_key_bits) for one party.
    sample_idx is relative to the sifted key.
    """
    sifted = select(bits, matching_indices(alice_bases, bob_bases))
    return select(sifted, sample_idx), remove_indices(sifted, sample_idx)
