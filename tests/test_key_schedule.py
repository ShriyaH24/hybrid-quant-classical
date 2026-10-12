"""
Checks for the two security-critical pieces:
  1. privacy amplification (Toeplitz hashing) is a proper 2-universal hash
  2. the hybrid key schedule only gives equal keys for identical handshakes
"""

import json
import os
import secrets
import socket
import struct
import threading

import pytest

from controller.handshake import derive_keys
from crypto.privacy import (new_toeplitz_seed, secret_key_length, toeplitz_hash,
                            toeplitz_seed_bytes)
from network.protocol import Session
from tests.conftest import run_epoch

# ------------------------------------------------------------------ Toeplitz

def test_toeplitz_matches_textbook_definition():
    """T[i][j] = d[i - j + n - 1], computed the slow way."""
    n, l = 40, 12
    x = [secrets.randbits(1) for _ in range(n)]
    seed = new_toeplitz_seed(n, l)
    d = [(seed[k // 8] >> (7 - k % 8)) & 1 for k in range(n + l - 1)]
    expected = [sum(d[i - j + n - 1] * x[j] for j in range(n)) % 2 for i in range(l)]
    assert toeplitz_hash(x, l, seed) == expected


def test_toeplitz_seed_is_full_length_and_checked():
    assert len(new_toeplitz_seed(1500, 800)) == toeplitz_seed_bytes(1500, 800) == (1500 + 800 - 1 + 7) // 8
    with pytest.raises(ValueError):
        toeplitz_hash([1] * 100, 40, b"\x00" * 16)          # a short seed is refused
    with pytest.raises(ValueError):
        toeplitz_hash([1] * 10, 20, new_toeplitz_seed(10, 20))   # cannot expand


def test_toeplitz_is_universal():
    """For x != y and a random matrix, Pr[T x = T y] should be ~2^-l."""
    n, l, trials = 64, 6, 4000
    collisions = 0
    for _ in range(trials):
        x = [secrets.randbits(1) for _ in range(n)]
        y = list(x)
        y[secrets.randbelow(n)] ^= 1
        seed = new_toeplitz_seed(n, l)
        collisions += toeplitz_hash(x, l, seed) == toeplitz_hash(y, l, seed)
    assert collisions / trials < 2.0 / 2 ** l               # expected 1/64 ~ 1.6 %


def test_key_length_is_whole_bytes():
    for q in (0.005, 0.01, 0.02, 0.03, 0.04):
        bits, _ = secret_key_length(1536, q, 512, 300, 64, 1e-9, 3.0)
        assert bits % 8 == 0

# ------------------------------------------------------------- key schedule

BASE = dict(gear=3, qkd_key=os.urandom(80), kem_ss=os.urandom(32), ecdh_ss=os.urandom(32),
            nonce_a=os.urandom(16), nonce_b=os.urandom(16), epoch=1, transcript=os.urandom(32))


def test_same_inputs_same_keys_and_keys_are_independent():
    k1, k2 = derive_keys(**BASE), derive_keys(**BASE)
    assert k1 == k2
    assert len({k1["session"], k1["confirm_alice"], k1["confirm_bob"]}) == 3


@pytest.mark.parametrize("field,value", [
    ("gear", 2), ("epoch", 2), ("transcript", os.urandom(32)),
    ("nonce_a", os.urandom(16)), ("nonce_b", os.urandom(16)),
    ("qkd_key", os.urandom(80)), ("kem_ss", os.urandom(32)),
])
def test_any_change_gives_a_different_key(field, value):
    assert derive_keys(**{**BASE, field: value})["session"] != derive_keys(**BASE)["session"]


def test_secrets_cannot_be_shifted_between_components():
    """Moving a byte from one secret to the other must change the KDF input."""
    from controller.handshake import _encode_secret
    a, b, c = os.urandom(32), b"\x01", os.urandom(31)
    split1 = _encode_secret(b"qkd", a + b) + _encode_secret(b"mlkem768", c)
    split2 = _encode_secret(b"qkd", a) + _encode_secret(b"mlkem768", b + c)
    assert split1 != split2          # plain concatenation would make these equal
    assert (a + b) + c == a + (b + c)


def test_gear_needs_its_secrets():
    with pytest.raises(ValueError):
        derive_keys(**{**BASE, "qkd_key": b""})              # Gear 3 without QKD
    with pytest.raises(ValueError):
        derive_keys(**{**BASE, "gear": 2, "kem_ss": b""})    # Gear 2 without ML-KEM

# ------------------------------------------------- tampering in the network

class TamperingProxy:
    """Sits between Alice and Bob and flips one byte of a chosen message type."""

    def __init__(self, target_type):
        self.a_user, self.a_proxy = socket.socketpair()
        self.b_proxy, self.b_user = socket.socketpair()
        self.target, self.tampered = target_type, False
        for src, dst in ((self.a_proxy, self.b_proxy), (self.b_proxy, self.a_proxy)):
            threading.Thread(target=self._pump, args=(src, dst), daemon=True).start()

    def _pump(self, src, dst):
        try:
            while True:
                hdr = self._exact(src, 4)
                raw = self._exact(src, struct.unpack(">I", hdr)[0])
                pkt = json.loads(raw)
                if pkt["type"] == self.target and not self.tampered:
                    field = next(k for k, v in pkt["payload"].items() if isinstance(v, str) and len(v) > 8)
                    v = pkt["payload"][field]
                    pkt["payload"][field] = ("0" if v[0] != "0" else "1") + v[1:]
                    raw = json.dumps(pkt, separators=(",", ":"), sort_keys=True).encode()
                    hdr = struct.pack(">I", len(raw))
                    self.tampered = True
                dst.sendall(hdr + raw)
        except OSError:
            return

    @staticmethod
    def _exact(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("closed")
            buf += chunk
        return buf


@pytest.mark.parametrize("target", ["KEM_CIPHERTEXT", "PRIVACY_SEED", "EPOCH_ACK"])
def test_tampering_means_nobody_gets_a_key(lab, target):
    proxy = TamperingProxy(target)
    lab.sa, lab.sb = Session(proxy.a_user), Session(proxy.b_user)
    a, b = run_epoch(lab)
    assert proxy.tampered
    assert isinstance(a, Exception) and isinstance(b, Exception)
