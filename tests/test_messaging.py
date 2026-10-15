"""
Two-way messaging between the real AliceNode and BobNode (reader threads,
Bob's worker, locks), over a socket pair or through Eve's classical tap.
"""

import socket
import threading
import time

import pytest

from alice.alice import AliceNode
from bob.bob import BobNode
from controller.handshake import seal
from network.relay import ClassicalTap


def wait_for(cond, timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


class Pair:
    def __init__(self, lab, through_tap=False, rekey_every=0):
        self.alice_log, self.bob_log, self.eve_log = [], [], []
        self.tap = None
        if through_tap:
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            self.tap = ClassicalTap("127.0.0.1", 0, "127.0.0.1", listener.getsockname()[1],
                                    log=self.eve_log.append).start()
            sa = socket.create_connection(self.tap.listen_addr)
            sb, _ = listener.accept()
            listener.close()
        else:
            sa, sb = socket.socketpair()
        self.alice = AliceNode(sa, lab.alice, rekey_every, out=self.alice_log.append).start_reader()
        self.bob = BobNode(sb, lab.bob, rekey_every, out=self.bob_log.append).start_reader().start_worker()

    def close(self):
        self.alice.close()
        self.bob.close()
        if self.tap:
            self.tap.stop()

    def texts(self, node):
        return [t for _, _, t in node.received]


@pytest.fixture
def pair(lab):
    p = Pair(lab)
    yield p
    p.close()


@pytest.fixture
def tapped(lab):
    p = Pair(lab, through_tap=True)
    yield p
    p.close()


def security_lines(log):
    return [line for line in log if "[SECURITY]" in line]

# ------------------------------------------------------------------ basics

def test_both_directions(pair):
    assert pair.alice.rekey("test")
    assert wait_for(lambda: pair.bob.current is not None)
    assert pair.alice.send_text("hello Bob")
    assert pair.bob.send_text("hello Alice")
    assert wait_for(lambda: pair.texts(pair.bob) == ["hello Bob"])
    assert wait_for(lambda: pair.texts(pair.alice) == ["hello Alice"])
    assert pair.alice.current.fingerprint == pair.bob.current.fingerprint


def test_many_messages_both_ways_in_order(pair):
    pair.alice.rekey("test")
    assert wait_for(lambda: pair.bob.current is not None)
    for i in range(20):
        pair.alice.send_text(f"a{i}")
        pair.bob.send_text(f"b{i}")
    assert wait_for(lambda: len(pair.bob.received) == 20 and len(pair.alice.received) == 20)
    assert pair.texts(pair.bob) == [f"a{i}" for i in range(20)]
    assert pair.texts(pair.alice) == [f"b{i}" for i in range(20)]


def test_bob_keeps_talking_while_alice_rekeys(pair):
    """Messages sent around a key exchange are neither lost nor break the exchange."""
    pair.alice.rekey("first")
    assert wait_for(lambda: pair.bob.current is not None)
    done = threading.Event()

    def chatter():
        i = 0
        while not done.is_set() and i < 200:
            if pair.bob.current is not None:
                pair.bob.send_text(f"during {i}")
                i += 1
            time.sleep(0.02)

    t = threading.Thread(target=chatter)
    t.start()
    ok = pair.alice.rekey("second")
    done.set()
    t.join()
    assert ok and pair.alice.current.epoch == 2
    sent = sum(1 for line in pair.bob_log if line.startswith("[SENT]"))
    assert wait_for(lambda: len(pair.alice.received) == sent)
    assert not security_lines(pair.alice_log)


def test_no_sending_without_a_key(pair):
    assert not pair.bob.send_text("too early")
    assert not pair.alice.send_text("too early")


def test_rotation_counts_both_directions(lab):
    p = Pair(lab, rekey_every=2)
    try:
        p.alice.rekey("start")
        assert wait_for(lambda: p.bob.current is not None)
        p.alice.send_text("one")
        p.bob.send_text("two")
        assert wait_for(lambda: p.alice.rotation_due.is_set())
        p.alice.rotate_if_due()
        assert p.alice.current.epoch == 2
    finally:
        p.close()

# ------------------------------------------------------------------ attacks on messages

def test_replayed_message_dropped(pair):
    pair.alice.rekey("test")
    assert wait_for(lambda: pair.bob.current is not None)
    payload = seal(pair.alice.current, "alice", 1, "once only")
    pair.bob._on_message(dict(payload))
    pair.bob._on_message(dict(payload))
    assert pair.texts(pair.bob) == ["once only"]
    assert any("replayed" in line for line in pair.bob_log)


def test_reflected_message_rejected(pair):
    """Bob's own ciphertext bounced back to him must not be accepted."""
    pair.alice.rekey("test")
    assert wait_for(lambda: pair.bob.current is not None)
    own = seal(pair.bob.current, "bob", 1, "my own words")
    pair.bob._on_message(own)
    forged = dict(own, **{"from": "alice"})            # relabelled: wrong key -> tag fails
    pair.bob._on_message(forged)
    assert pair.texts(pair.bob) == []
    assert len(security_lines(pair.bob_log)) == 2


def test_direction_keys_differ(pair):
    pair.alice.rekey("test")
    k = pair.alice.current
    assert k.alice_to_bob != k.bob_to_alice

# ------------------------------------------------------------------ Eve's classical tap

def test_eve_sees_only_ciphertext(tapped):
    assert tapped.alice.rekey("through Eve")
    assert wait_for(lambda: tapped.bob.current is not None)
    tapped.alice.send_text("meet at the library at 5")
    tapped.bob.send_text("see you there")
    assert wait_for(lambda: tapped.texts(tapped.bob) == ["meet at the library at 5"])
    assert wait_for(lambda: tapped.texts(tapped.alice) == ["see you there"])
    eve = "\n".join(tapped.eve_log)
    assert "intercepted alice->bob" in eve and "intercepted bob->alice" in eve
    assert "library" not in eve and "see you there" not in eve


def test_eve_tampers_a_message(tapped):
    tapped.alice.rekey("through Eve")
    assert wait_for(lambda: tapped.bob.current is not None)
    tapped.tap.tamper = "message"
    tapped.alice.send_text("tampered in transit")
    tapped.alice.send_text("arrives intact")
    assert wait_for(lambda: tapped.texts(tapped.bob) == ["arrives intact"])
    assert any("rejected" in line for line in security_lines(tapped.bob_log))


def test_eve_tampers_the_handshake_then_link_recovers(tapped):
    tapped.tap.tamper = "handshake"
    assert not tapped.alice.rekey("Eve tampers")             # nobody gets a key ...
    assert wait_for(lambda: tapped.bob.current is None)
    assert not tapped.alice.send_text("blocked")
    assert tapped.alice.rekey("Eve stopped")                  # ... and the next epoch works
    assert wait_for(lambda: tapped.bob.current is not None and tapped.bob.current.epoch == 2)
    tapped.bob.send_text("we're fine")
    assert wait_for(lambda: tapped.texts(tapped.alice) == ["we're fine"])
