import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from controller.gear_controller import GearController            # noqa: E402
from controller.handshake import NodeContext, alice_run_epoch, bob_handle_epoch  # noqa: E402
from crypto import classical, pqc                                  # noqa: E402
from crypto.identity import Identity, PeerKeys                     # noqa: E402
from network.protocol import Session                               # noqa: E402
from quantum.channel import QuantumChannel                         # noqa: E402
from quantum.channel_server import ChannelServer                   # noqa: E402

TEST_QUBITS = 4096


def _make_identity(name):
    ed_sk, ed_pk = classical.ed25519_keypair()
    ml_sk, ml_pk = pqc.sig_keypair()
    return Identity(name, ed_sk, ed_pk, ml_sk, ml_pk)


@pytest.fixture(scope="session")
def identities():
    a, b = _make_identity("alice"), _make_identity("bob")
    return {
        "alice": a, "bob": b,
        "alice_pub": PeerKeys("alice", a.ed25519_public, a.mldsa_public),
        "bob_pub": PeerKeys("bob", b.ed25519_public, b.mldsa_public),
    }


@pytest.fixture
def lab(identities):
    """A running channel server plus Alice/Bob contexts connected by a socket pair."""
    channel = QuantumChannel(noise=0.02)
    server = ChannelServer(channel, port=0, verbose=False).start()
    addr = ("127.0.0.1", server.port)
    alice = NodeContext("alice", identities["alice"], identities["bob_pub"], GearController("alice"),
                        addr, qubits=TEST_QUBITS, verbose=False)
    bob = NodeContext("bob", identities["bob"], identities["alice_pub"], GearController("bob"),
                      addr, verbose=False)
    sa, sb = socket.socketpair()
    lab = type("Lab", (), {})()
    lab.channel, lab.alice, lab.bob = channel, alice, bob
    lab.sa, lab.sb = Session(sa), Session(sb)
    yield lab
    server.stop()
    sa.close()
    sb.close()


def run_epoch(lab, epoch=1):
    """Run one epoch with Bob in a thread. Returns (alice_result, bob_result) - keys or exceptions."""
    out = {}

    def bob():
        try:
            out["bob"] = bob_handle_epoch(lab.sb, lab.bob, lab.sb.recv())
        except Exception as exc:
            out["bob"] = exc

    t = threading.Thread(target=bob)
    t.start()
    try:
        out["alice"] = alice_run_epoch(lab.sa, lab.alice, epoch)
    except Exception as exc:
        out["alice"] = exc
    t.join(timeout=120)
    return out["alice"], out["bob"]
