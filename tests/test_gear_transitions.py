"""
End-to-end: real Qiskit channel, real Cascade, real ML-KEM/ML-DSA/X25519.
Each test checks the gear BOTH sides chose and that their keys match.
"""

import pytest

from controller.handshake import EpochKey, seal, open_sealed
from tests.conftest import run_epoch


def agree(a, b, gear):
    assert isinstance(a, EpochKey), a
    assert isinstance(b, EpochKey), b
    assert a.gear == b.gear == gear
    assert a.alice_to_bob == b.alice_to_bob and a.bob_to_alice == b.bob_to_alice
    assert len(a.alice_to_bob) == 32 and a.alice_to_bob != a.bob_to_alice


def test_healthy_channel_gear3(lab):
    a, b = run_epoch(lab)
    agree(a, b, 3)
    assert open_sealed(b, seal(a, "alice", 1, "hello"), "alice") == "hello"
    assert open_sealed(a, seal(b, "bob", 1, "hi back"), "bob") == "hi back"


def test_eve_forces_gear2(lab):
    lab.channel.eve = True
    a, b = run_epoch(lab)
    agree(a, b, 2)
    assert any("QBER" in r for r in lab.alice.gears.history[-1].reasons)
    assert lab.alice.gears.history[-1].qber > 0.11


def test_link_down_forces_gear2(lab):
    lab.channel.link_up = False
    a, b = run_epoch(lab)
    agree(a, b, 2)
    assert any("Quantum channel failure" in r for r in lab.alice.gears.history[-1].reasons)


def test_no_qkd_no_pqc_gear1(lab):
    lab.channel.link_up = False
    lab.alice.pqc_enabled = False
    a, b = run_epoch(lab)
    agree(a, b, 1)


def test_qkd_ok_but_peer_lacks_pqc_gear1(lab):
    lab.bob.pqc_enabled = False
    a, b = run_epoch(lab)
    agree(a, b, 1)


def test_min_gear_policy_aborts(lab):
    lab.channel.link_up = False
    lab.alice.pqc_enabled = False
    lab.bob.gears.min_gear = 2
    a, b = run_epoch(lab)
    assert isinstance(a, Exception) and isinstance(b, Exception)


def test_downshift_and_recovery_sequence(lab):
    """3 -> 2 (Eve) -> 1 (link down + no PQC) -> 3 (everything restored)."""
    agree(*run_epoch(lab, 1), 3)
    lab.channel.eve = True
    agree(*run_epoch(lab, 2), 2)
    lab.channel.eve = False
    lab.channel.link_up = False
    lab.alice.pqc_enabled = False
    agree(*run_epoch(lab, 3), 1)
    lab.channel.link_up = True
    lab.alice.pqc_enabled = True
    agree(*run_epoch(lab, 4), 3)
    assert [h.gear for h in lab.alice.gears.history] == [3, 2, 1, 3]
    assert [h.gear for h in lab.bob.gears.history] == [3, 2, 1, 3]


def test_forged_identity_rejected(lab, identities):
    """Bob pinned a different Alice key -> signature check fails, nobody gets a key."""
    from tests.conftest import _make_identity
    lab.alice.identity = _make_identity("mallory")
    a, b = run_epoch(lab)
    assert isinstance(b, Exception) and isinstance(a, Exception)


def test_old_epoch_message_rejected(lab):
    k1, _ = run_epoch(lab, 1)
    _, k2 = run_epoch(lab, 2)
    with pytest.raises(ValueError):
        open_sealed(k2, seal(k1, "alice", 1, "replayed from epoch 1"), "alice")
