import random
import secrets

import pytest

from controller.gear_controller import Observations, select_gear
from crypto.bb84 import calculate_qber, random_bases, random_bits, sift_and_sample
from crypto.error_correction import (answer_queries, block_sizes, initial_block_size,
                                     make_permutations, reconcile)
from crypto.privacy import secret_key_length, toeplitz_hash
from quantum.channel import QuantumChannel, QuantumLinkError


@pytest.mark.parametrize("qkd_bits,pqc_a,pqc_b,gear", [
    (512, True, True, 3),
    (0, True, True, 2),       # QKD failed
    (512, True, False, 1),    # peer lacks PQC
    (0, False, True, 1),
    (0, False, False, 1),
])
def test_gear_table(qkd_bits, pqc_a, pqc_b, gear):
    assert select_gear(Observations(qkd_key_bits=qkd_bits, pqc_local=pqc_a, pqc_peer=pqc_b)) == gear


@pytest.mark.parametrize("q", [0.01, 0.03, 0.06])
def test_cascade_corrects(q):
    n = 1500
    bob = random_bits(n)
    alice = [b ^ (random.random() < q) for b in bob]
    perms = make_permutations(n, secrets.randbits(64), 6)
    key, leaked, _ = reconcile(alice, perms, block_sizes(initial_block_size(q), 6, n),
                               lambda qs: answer_queries(bob, perms, qs))
    assert key == bob
    assert leaked < n


def test_toeplitz_is_deterministic_and_compresses():
    from crypto.privacy import new_toeplitz_seed
    bits = random_bits(1000)
    seed = new_toeplitz_seed(1000, 296)
    out = toeplitz_hash(bits, 296, seed)
    assert out == toeplitz_hash(bits, 296, seed) and len(out) == 296


def test_key_length_shrinks_with_qber():
    lengths = [secret_key_length(1500, q, 500, int(1500 * 0.2), 64, 1e-9, 3)[0] for q in (0.01, 0.03, 0.05)]
    assert lengths[0] > lengths[1] > lengths[2]
    assert secret_key_length(1500, 0.11, 500, 900, 64, 1e-9, 3)[0] == 0


def _channel_qber(ch, n=3000):
    a, A, B = random_bits(n), random_bases(n), random_bases(n)
    b, _ = ch.transmit(a, A, B)
    idx = list(range(sum(x == y for x, y in zip(A, B))))
    sa, _ = sift_and_sample(a, A, B, idx)
    sb, _ = sift_and_sample(b, A, B, idx)
    return calculate_qber(sa, sb)


def test_channel_noise_matches_setting():
    assert 0.0 < _channel_qber(QuantumChannel(noise=0.04)) < 0.08


def test_eve_raises_qber_above_threshold():
    assert _channel_qber(QuantumChannel(noise=0.0, eve=True)) > 0.18


def test_link_down():
    with pytest.raises(QuantumLinkError):
        QuantumChannel(link_up=False).transmit([0], [0], [0])
