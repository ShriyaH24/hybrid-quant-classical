"""
tests/test_cascade.py

Thorough validation of Cascade information reconciliation.

Every test builds Bob's key, copies it to Alice and flips a KNOWN set of
bits, so we know exactly which errors exist. Cascade must then:
  * make Alice's key identical to Bob's,
  * correct exactly the injected positions (never a correct bit),
  * account for every parity bit Bob revealed,
  * work for any QBER up to the 11 % bound, any error pattern and any
    public permutation seed.

The last section runs real epochs and forces reconciliation to fail,
checking that both sides discard the QKD key - and abort the whole epoch
when policy demands Gear 3.
"""

import math
import secrets

import pytest

from controller import handshake
from crypto.error_correction import (answer_queries, block_sizes, initial_block_size,
                                     make_permutations, range_parity, reconcile, validate_queries)
from crypto.key_verification import tags_match, verification_tag
from crypto.privacy import binary_entropy, qber_upper_bound
from tests.conftest import run_epoch

PASSES = 6
RNG = secrets.SystemRandom()


# =====================================================================
# helpers
# =====================================================================

def make_keys(n, error_positions):
    """Bob's random key, and Alice's copy with the given bits flipped."""
    bob = [secrets.randbits(1) for _ in range(n)]
    alice = list(bob)
    for p in error_positions:
        alice[p] ^= 1
    return alice, bob


class CountingBob:
    """Bob's side of the parity protocol, counting every bit he reveals."""

    def __init__(self, key, perms):
        self.key, self.perms = key, perms
        self.revealed = 0
        self.round_trips = 0

    def __call__(self, queries):
        for p, s, e in queries:                         # sanity: queries are well-formed
            assert 0 <= p < len(self.perms) and 0 <= s < e <= len(self.key)
        self.revealed += len(queries)
        self.round_trips += 1
        return answer_queries(self.key, self.perms, queries)


def run_cascade(alice, bob, qber_estimate, seed=None, passes=PASSES):
    """One reconciliation the way the handshake does it. Returns (key, leaked, fixed, bob_oracle)."""
    n = len(bob)
    seed = secrets.randbits(64) if seed is None else seed
    perms = make_permutations(n, seed, passes)
    k1 = initial_block_size(qber_upper_bound(qber_estimate, max(1, n // 3), 2.0))
    oracle = CountingBob(bob, perms)
    key, leaked, fixed = reconcile(alice, perms, block_sizes(k1, passes, n), oracle)
    return key, leaked, fixed, oracle


def assert_recovered(alice, bob, errors, qber_estimate, seed=None):
    original = list(alice)
    key, leaked, fixed, oracle = run_cascade(alice, bob, qber_estimate, seed)
    assert key == bob, f"{sum(a != b for a, b in zip(key, bob))} errors left"
    assert fixed == len(errors), "Cascade must flip exactly the erroneous bits"
    assert leaked == oracle.revealed, "every parity Bob revealed must be counted"
    assert alice == original, "reconcile must not modify its input"
    return leaked, oracle


# =====================================================================
# 1. building blocks
# =====================================================================

def test_permutations_are_valid_and_shared():
    perms = make_permutations(1000, 12345, PASSES)
    assert len(perms) == PASSES
    for p in perms:
        assert sorted(p) == list(range(1000))              # a true permutation
    assert make_permutations(1000, 12345, PASSES) == perms  # same seed -> Alice and Bob agree
    assert make_permutations(1000, 54321, PASSES) != perms  # new seed -> new shuffle
    assert len({tuple(p) for p in perms}) == PASSES         # every pass shuffles differently


def test_block_sizes_double_and_are_capped():
    assert block_sizes(8, 6, 1536) == [8, 16, 32, 64, 128, 256]
    assert block_sizes(100, 6, 1536) == [100, 200, 384, 384, 384, 384]   # cap = n / 4
    assert all(s >= 4 for s in block_sizes(4, 6, 8))


def test_initial_block_size_follows_qber():
    sizes = [initial_block_size(q) for q in (0.005, 0.01, 0.03, 0.05, 0.11)]
    assert sizes == sorted(sizes, reverse=True)             # more noise -> smaller blocks
    assert initial_block_size(0.0) <= 512 and initial_block_size(0.5) >= 4


def test_range_parity_matches_direct_count():
    key = [secrets.randbits(1) for _ in range(300)]
    perm = make_permutations(300, 7, 1)[0]
    for s, e in [(0, 300), (0, 1), (17, 93), (299, 300)]:
        assert range_parity(key, perm, s, e) == sum(key[perm[i]] for i in range(s, e)) % 2


# =====================================================================
# 2. recovery across QBERs
# =====================================================================

@pytest.mark.parametrize("qber", [0.0, 0.002, 0.01, 0.02, 0.03, 0.05, 0.07, 0.09, 0.11])
@pytest.mark.parametrize("trial", range(4))
def test_recovers_key_across_qber(qber, trial):
    n = 1536
    errors = RNG.sample(range(n), round(qber * n))
    alice, bob = make_keys(n, errors)
    assert_recovered(alice, bob, errors, qber)


def test_no_errors_means_no_corrections():
    n = 1536
    alice, bob = make_keys(n, [])
    key, leaked, fixed, oracle = run_cascade(alice, bob, 0.0)
    assert key == bob and fixed == 0
    k1 = initial_block_size(qber_upper_bound(0.0, n // 3, 2.0))
    top_level = sum(math.ceil(n / s) for s in block_sizes(k1, PASSES, n))
    assert leaked == top_level                               # only one parity per block


def test_leak_is_close_to_the_shannon_limit():
    """Cascade cannot beat n*h(QBER) and should stay within ~1.5x of it."""
    n = 1536
    for q in (0.01, 0.03, 0.05):
        errors = RNG.sample(range(n), round(q * n))
        alice, bob = make_keys(n, errors)
        leaked, _ = assert_recovered(alice, bob, errors, q)
        shannon = n * binary_entropy(q)
        assert shannon * 0.9 <= leaked <= shannon * 1.6 + 60, (q, leaked, shannon)


def test_wrong_qber_estimate_still_recovers():
    """The sample may under- or over-estimate the true error rate."""
    n = 1536
    errors = RNG.sample(range(n), round(0.04 * n))
    for guess in (0.01, 0.04, 0.10):
        alice, bob = make_keys(n, errors)
        assert_recovered(alice, bob, errors, guess)


# =====================================================================
# 3. error patterns
# =====================================================================

def _patterns(n):
    return {
        "single bit at start": [0],
        "single bit at end": [n - 1],
        "first and last": [0, n - 1],
        "burst of 24 adjacent bits": list(range(500, 524)),
        "two bursts": list(range(100, 116)) + list(range(1200, 1216)),
        "pairs hidden in one block": [10, 11, 40, 41, 300, 301, 302, 303],
        "periodic every 50th bit": list(range(7, n, 50)),
        "periodic every 9th bit": list(range(3, n, 9)),
        "dense front quarter": RNG.sample(range(n // 4), n // 40),
        "all in the last 64 bits": list(range(n - 64, n, 2)),
    }


@pytest.mark.parametrize("name", list(_patterns(1536)))
def test_recovers_structured_error_patterns(name):
    n = 1536
    errors = _patterns(n)[name]
    qber = len(errors) / n
    for _ in range(3):                                      # different shuffles each time
        alice, bob = make_keys(n, errors)
        assert_recovered(alice, bob, errors, qber)


@pytest.mark.parametrize("bob_bits", ["all zeros", "all ones", "alternating"])
def test_recovers_on_degenerate_keys(bob_bits):
    n = 1024
    bob = {"all zeros": [0] * n, "all ones": [1] * n,
           "alternating": [i % 2 for i in range(n)]}[bob_bits]
    errors = RNG.sample(range(n), 30)
    alice = list(bob)
    for p in errors:
        alice[p] ^= 1
    assert_recovered(alice, bob, errors, 30 / n)


@pytest.mark.parametrize("n", [1, 2, 7, 33, 257, 1537, 4099])
def test_odd_key_lengths(n):
    errors = RNG.sample(range(n), max(1, n // 40)) if n > 1 else [0]
    alice, bob = make_keys(n, errors)
    assert_recovered(alice, bob, errors, len(errors) / n)


# =====================================================================
# 4. random permutations
# =====================================================================

def test_same_errors_many_permutation_seeds():
    n = 1536
    errors = RNG.sample(range(n), 46)                        # 3 %
    alice, bob = make_keys(n, errors)
    for seed in [0, 1, 2, 2 ** 31 - 1, 2 ** 63 - 1] + [secrets.randbits(64) for _ in range(15)]:
        assert_recovered(list(alice), bob, errors, 0.03, seed=seed)


def test_mismatched_seeds_break_reconciliation():
    """If Alice and Bob shuffled differently, Cascade must NOT silently succeed -
    and must still terminate (an inconsistent peer cannot make Alice loop forever)."""
    n = 1536
    errors = RNG.sample(range(n), 46)
    alice, bob = make_keys(n, errors)
    k1 = initial_block_size(0.03)
    alice_perms = make_permutations(n, 111, PASSES)
    bob_perms = make_permutations(n, 222, PASSES)
    key, _, _ = reconcile(alice, alice_perms, block_sizes(k1, PASSES, n),
                          lambda qs: answer_queries(bob, bob_perms, qs))
    assert key != bob


def test_statistical_success_rate():
    """300 random runs at realistic QBERs with a SAMPLED estimate, as in the handshake."""
    n, fails = 1536, 0
    for _ in range(300):
        q = RNG.choice([0.01, 0.02, 0.03, 0.05, 0.08])
        errors = RNG.sample(range(n), round(q * n))
        alice, bob = make_keys(n, errors)
        sample = RNG.sample(range(n), 512)
        q_est = sum(alice[i] != bob[i] for i in sample) / 512
        key, _, _, _ = run_cascade(alice, bob, q_est)
        fails += key != bob
    assert fails <= 3, f"{fails}/300 reconciliations failed"


# =====================================================================
# 5. verification after Cascade
# =====================================================================

def test_verification_tag_catches_every_single_bit_difference():
    key = [secrets.randbits(1) for _ in range(256)]
    nonce = secrets.token_bytes(16)
    good = verification_tag(key, nonce)
    assert tags_match(good, verification_tag(list(key), nonce))
    for i in range(len(key)):
        other = list(key)
        other[i] ^= 1
        assert not tags_match(good, verification_tag(other, nonce))


def test_verification_tag_depends_on_nonce():
    key = [secrets.randbits(1) for _ in range(256)]
    assert verification_tag(key, b"\x00" * 16) != verification_tag(key, b"\x01" * 16)


# =====================================================================
# 6. full epochs: reconciliation verification failure -> abort
# =====================================================================

def _corrupting_reconcile(real):
    """Run real Cascade, then leave one error behind (as a failed Cascade would)."""
    def wrapped(alice_key, perms, sizes, ask):
        key, leaked, fixed = real(alice_key, perms, sizes, ask)
        key = list(key)
        key[len(key) // 2] ^= 1
        return key, leaked, fixed
    return wrapped


def _lying_bob(real):
    """Bob reveals one wrong parity - Alice 'corrects' a good bit."""
    state = {"lied": False}

    def wrapped(key, perms, queries):
        answers = real(key, perms, queries)
        if not state["lied"] and answers:
            answers = list(answers)
            answers[0] ^= 1
            state["lied"] = True
        return answers
    return wrapped


@pytest.mark.parametrize("fault", ["alice keeps an error", "bob reveals a wrong parity"])
def test_failed_verification_discards_qkd_key_on_both_sides(lab, monkeypatch, fault):
    if fault == "alice keeps an error":
        monkeypatch.setattr(handshake, "reconcile", _corrupting_reconcile(handshake.reconcile))
    else:
        monkeypatch.setattr(handshake, "answer_queries", _lying_bob(handshake.answer_queries))

    a, b = run_epoch(lab)

    # neither side used a QKD key: both fell back to Gear 2 together, for the same reason.
    # A lie is caught either by the verification tag ("differ after Cascade") or, when
    # backtracking repairs it at great cost, by privacy amplification ("secret bits
    # survive") - both are safe outcomes.
    assert a.gear == b.gear == 2 and a.alice_to_bob == b.alice_to_bob
    reasons = []
    for ctx in (lab.alice, lab.bob):
        record = ctx.gears.history[-1]
        assert record.gear == 2
        assert any("differ after Cascade" in r or "secret bits survive" in r for r in record.reasons), record.reasons
        reasons.append(record.reasons)
    assert reasons[0] == reasons[1]


def test_failed_verification_aborts_epoch_when_gear3_required(lab, monkeypatch):
    monkeypatch.setattr(handshake, "reconcile", _corrupting_reconcile(handshake.reconcile))
    lab.alice.gears.min_gear = 3
    lab.bob.gears.min_gear = 3

    a, b = run_epoch(lab)

    assert isinstance(a, Exception), "Alice must abort"
    assert isinstance(b, Exception), "Bob must abort"
    assert "minimum Gear 3" in str(a) or "aborted" in str(a).lower()
    assert lab.alice.gears.history == [] and lab.bob.gears.history == []   # no key committed


def test_successful_reconciliation_still_reaches_gear3(lab):
    """Control case: with no fault injected, the same setup lands in Gear 3."""
    a, b = run_epoch(lab)
    assert a.gear == b.gear == 3 and a.alice_to_bob == b.alice_to_bob


def test_both_sides_count_the_same_leak(lab):
    """Privacy amplification is sized independently by Alice and Bob, so their
    count of revealed parities must agree exactly."""
    a, b = run_epoch(lab)
    ra, rb = lab.alice.gears.history[-1], lab.bob.gears.history[-1]
    assert a.gear == 3 and ra.ec_leaked == rb.ec_leaked > 0


# =====================================================================
# 7. Bob refuses malformed parity requests
# =====================================================================

@pytest.mark.parametrize("bad", [
    "not a list", [[0, 0]], [[0, 0, 1, 2]], [[-1, 0, 4]], [[6, 0, 4]],
    [[0, 5, 5]], [[0, 8, 4]], [[0, 0, 101]], [[0, "0", 4]], [[0, 0.0, 4]],
])
def test_bob_rejects_malformed_queries(bad):
    with pytest.raises(ValueError):
        validate_queries(bad, 100, PASSES)


def test_bob_accepts_well_formed_queries():
    assert validate_queries([[0, 0, 100], [5, 99, 100]], 100, PASSES) == [(0, 0, 100), (5, 99, 100)]


def test_inconsistent_parities_terminate_within_budget():
    """A peer answering at random must not hang Alice or make her reveal unbounded parity."""
    from crypto.error_correction import MAX_LEAK_FRACTION
    n = 1536
    alice, _ = make_keys(n, [])
    perms = make_permutations(n, 9, PASSES)
    key, leaked, _ = reconcile(alice, perms, block_sizes(initial_block_size(0.03), PASSES, n),
                               lambda qs: [secrets.randbits(1) for _ in qs])
    assert leaked <= MAX_LEAK_FRACTION * n + 64 + n      # budget + at most one final batch
