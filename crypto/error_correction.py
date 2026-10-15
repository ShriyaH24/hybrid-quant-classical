"""
crypto/error_correction.py

Cascade-style information reconciliation (shuffled, multi-pass, batched).

Design
------
* Bob's key never changes. He only answers "what is the parity of
  these positions?" queries.
* Alice corrects HER copy to match Bob's, so no correction indices
  need to be sent.
* Every pass uses a fresh public permutation (derived from a shared
  seed), so errors that hid in pairs in one pass get split up in the
  next one. Without shuffling, passes 2+ can never find anything.
* Every parity Bob reveals is counted in `leaked`; privacy
  amplification later removes exactly that much information.

Queries are batched: one network round trip per pass level, not per
block, so a 4-pass run on ~1500 bits takes ~30 round trips.
"""

from typing import Callable, List, Sequence, Tuple

import numpy as np

# Stop reconciling once this share of the key has been revealed as parities:
# beyond it nothing secret is left, and it bounds the work an inconsistent
# (faulty or malicious) peer can force on Alice.
MAX_LEAK_FRACTION = 0.75

# (pass_index, start, end) on the permuted key -> parity bit
Query = Tuple[int, int, int]
ParityOracle = Callable[[List[Query]], List[int]]


def initial_block_size(qber: float) -> int:
    """Classic Cascade heuristic k1 ~= 0.73 / QBER."""
    return int(max(4, min(512, round(0.73 / max(qber, 0.005)))))


def block_sizes(k1: int, passes: int, n: int) -> List[int]:
    """Double each pass, but cap at n/4 so late passes still split the key
    into several shuffled blocks (one giant block finds nothing)."""
    cap = max(4, n // 4)
    return [min(k1 * (2 ** i), cap) for i in range(passes)]


def make_permutations(n: int, seed: int, passes: int) -> List[List[int]]:
    rng = np.random.default_rng(seed)
    return [rng.permutation(n).tolist() for _ in range(passes)]


def range_parity(key: Sequence[int], perm: Sequence[int], start: int, end: int) -> int:
    p = 0
    for i in range(start, end):
        p ^= key[perm[i]]
    return p


def validate_queries(raw, n: int, passes: int) -> List[Query]:
    """
    Bob's side: check every parity query before answering it. A query is
    (pass, start, end) with 0 <= pass < passes and 0 <= start < end <= n.
    Anything else (wrong shape, out of range, empty range) aborts the epoch
    instead of crashing Bob or answering about bits that do not exist.
    """
    if not isinstance(raw, list) or len(raw) > 4 * n + 16:
        raise ValueError("parity request has the wrong shape")
    out = []
    for q in raw:
        if not (isinstance(q, (list, tuple)) and len(q) == 3 and all(isinstance(v, int) for v in q)):
            raise ValueError(f"malformed parity query {q!r}")
        p, s, e = q
        if not (0 <= p < passes and 0 <= s < e <= n):
            raise ValueError(f"parity query out of range {q!r}")
        out.append((p, s, e))
    return out


def answer_queries(key: Sequence[int], perms: List[List[int]], queries: List[Query]) -> List[int]:
    """Bob's side: compute the parities Alice asked for."""
    return [range_parity(key, perms[p], s, e) for p, s, e in queries]


def _bisect_all(key: List[int],
                perms: List[List[int]],
                ranges: List[Query],
                ask: ParityOracle) -> Tuple[List[int], int]:
    """
    Binary-search several odd-parity ranges in parallel (one round trip
    per halving step). Returns (key_indices_in_error, parities_leaked).
    """
    leaked = 0
    pending = list(ranges)
    found = []
    while pending:
        queries = []
        for p, s, e in pending:
            if e - s == 1:
                found.append(perms[p][s])
            else:
                queries.append((p, s, (s + e) // 2, e))
        if not queries:
            break
        bob_half = ask([(p, s, m) for p, s, m, _ in queries])
        leaked += len(queries)
        pending = []
        for (p, s, m, e), bp in zip(queries, bob_half):
            if range_parity(key, perms[p], s, m) != bp:
                pending.append((p, s, m))
            else:
                pending.append((p, m, e))
    return found, leaked


def reconcile(alice_key: Sequence[int],
              perms: List[List[int]],
              sizes: List[int],
              ask: ParityOracle) -> Tuple[List[int], int, int]:
    """
    Alice's side of Cascade. Returns (corrected_key, parities_leaked, corrections).

    The "cascade" step: fixing a bit flips the parity of the block that
    contains it in every EARLIER pass. Those blocks now show an odd
    error count, so they are searched again - this is what removes the
    error pairs a single pass cannot see.
    """
    key = list(alice_key)
    n = len(key)
    leaked = 0
    corrections = 0

    inverse = []                 # inverse[p][key_index] -> position in perm p
    for perm in perms:
        inv = [0] * n
        for pos, idx in enumerate(perm):
            inv[idx] = pos
        inverse.append(inv)

    bob_blocks: List[List[int]] = []   # Bob's parity for every top-level block, per pass

    def block_range(p: int, b: int) -> Tuple[int, int]:
        return b * sizes[p], min((b + 1) * sizes[p], n)

    def is_odd(p: int, b: int) -> bool:
        s, e = block_range(p, b)
        return range_parity(key, perms[p], s, e) != bob_blocks[p][b]

    # Termination guard. With honest answers Cascade always ends, but if Bob's
    # parities are inconsistent (a faulty peer, a tampered PARITY_RESPONSE, a
    # seed mismatch) the backtracking can cycle forever. Past this budget no
    # secret key could survive anyway (privacy amplification subtracts every
    # revealed parity), so stop and let the verification tag reject the key.
    max_leak = int(MAX_LEAK_FRACTION * n) + 64
    max_rounds = 4 * n + 64
    rounds = 0

    for p in range(len(perms)):
        count = (n + sizes[p] - 1) // sizes[p]
        bob_blocks.append(ask([(p, *block_range(p, b)) for b in range(count)]))
        leaked += count

        odd = {(p, b) for b in range(count) if is_odd(p, b)}
        while odd:
            rounds += 1
            if leaked > max_leak or rounds > max_rounds:
                return key, leaked, corrections
            ranges = [(q, *block_range(q, b)) for q, b in sorted(odd)]
            errors, used = _bisect_all(key, perms, ranges, ask)
            leaked += used
            flipped = set(errors)
            for idx in flipped:
                key[idx] ^= 1
                corrections += 1
            # re-check every block (this pass and earlier ones) touching a flipped bit
            odd = set()
            for idx in flipped:
                for q in range(p + 1):
                    b = inverse[q][idx] // sizes[q]
                    if is_odd(q, b):
                        odd.add((q, b))

    return key, leaked, corrections
