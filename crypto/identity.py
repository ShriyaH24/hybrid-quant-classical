"""
crypto/identity.py

Long-term identity keys for Alice and Bob.

BB84 (and every gear) needs an AUTHENTICATED classical channel,
otherwise a man-in-the-middle simply runs the protocol with each side.
Each node signs the handshake transcript with its long-term key and
verifies the peer against a public key it already has ("pinned").

Generate once (from the project root):

    python -m crypto.identity                 # one machine: both parties
    python -m crypto.identity --party alice   # Alice's machine: only Alice's keys
    python -m crypto.identity --party bob     # Bob's machine: only Bob's keys

On separate machines each party keeps its private key (*.key) to itself
and copies only its PUBLIC keys (*.pub) to the other machine's keys/
folder (USB stick, email - public keys are not secret).
"""

import argparse
import os
from dataclasses import dataclass
from typing import Optional

from crypto import classical, pqc

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KEY_DIR = os.path.join(ROOT, "keys")
PARTIES = ("alice", "bob")


@dataclass
class Identity:
    name: str
    ed25519_private: bytes
    ed25519_public: bytes
    mldsa_private: Optional[bytes]   # None if PQC was unavailable at keygen
    mldsa_public: Optional[bytes]


@dataclass
class PeerKeys:
    name: str
    ed25519_public: bytes
    mldsa_public: Optional[bytes]


def _path(name: str, kind: str) -> str:
    return os.path.join(KEY_DIR, f"{name}_{kind}")


def _read(path: str) -> Optional[bytes]:
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def generate_all(force: bool = False, parties=PARTIES) -> None:
    os.makedirs(KEY_DIR, exist_ok=True)
    for name in parties:
        if os.path.exists(_path(name, "ed25519.key")) and not force:
            print(f"[KEYS] {name}: keys already exist (use --force to replace)")
            continue
        sk, pk = classical.ed25519_keypair()
        _write(_path(name, "ed25519.key"), sk)
        _write(_path(name, "ed25519.pub"), pk)
        if pqc.PQC_AVAILABLE:
            sk, pk = pqc.sig_keypair()
            _write(_path(name, "mldsa65.key"), sk)
            _write(_path(name, "mldsa65.pub"), pk)
            print(f"[KEYS] {name}: Ed25519 + ML-DSA-65 key pairs written to keys/")
        else:
            print(f"[KEYS] {name}: Ed25519 only (PQC unavailable: {pqc.PQC_ERROR})")


def load_identity(name: str) -> Identity:
    sk = _read(_path(name, "ed25519.key"))
    if sk is None:
        raise SystemExit(
            f"\n[KEYS] No identity keys for '{name}'. Run this once from the project root:\n"
            f"       python -m crypto.identity\n"
        )
    return Identity(
        name=name,
        ed25519_private=sk,
        ed25519_public=_read(_path(name, "ed25519.pub")),
        mldsa_private=_read(_path(name, "mldsa65.key")),
        mldsa_public=_read(_path(name, "mldsa65.pub")),
    )


def load_peer(name: str) -> PeerKeys:
    pk = _read(_path(name, "ed25519.pub"))
    if pk is None:
        raise SystemExit(f"[KEYS] Missing {name.capitalize()}'s public key. On one machine run: "
                         f"python -m crypto.identity\n       On separate machines copy {name}_ed25519.pub "
                         f"and {name}_mldsa65.pub from {name.capitalize()}'s keys/ folder into this keys/ folder.")
    return PeerKeys(name=name, ed25519_public=pk, mldsa_public=_read(_path(name, "mldsa65.pub")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Alice/Bob identity keys")
    parser.add_argument("--force", action="store_true", help="overwrite existing keys")
    parser.add_argument("--party", choices=PARTIES, help="only this party's keys (one per machine)")
    args = parser.parse_args()
    generate_all(args.force, (args.party,) if args.party else PARTIES)
    if args.party:
        other = "bob" if args.party == "alice" else "alice"
        print(f"\nNow copy these PUBLIC files to the keys/ folder on {other.capitalize()}'s machine:")
        for kind in ("ed25519.pub", "mldsa65.pub"):
            print(f"    keys/{args.party}_{kind}")
        print(f"and copy {other}_ed25519.pub + {other}_mldsa65.pub from there into this keys/ folder.")
