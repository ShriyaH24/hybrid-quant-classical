"""
bob/bob.py

Bob: answers each key-establishment epoch and decrypts Alice's messages.

Run (after the channel server, before Alice):
    python bob/bob.py
    python bob/bob.py --no-pqc       # Bob has no post-quantum support
    python bob/bob.py --min-gear 2   # refuse quantum-vulnerable Gear 1
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography.exceptions import InvalidTag                       # noqa: E402

from controller import config                                       # noqa: E402
from controller.gear_controller import GearController                # noqa: E402
from controller.handshake import (AuthenticationError, EpochAborted,  # noqa: E402
                                  NodeContext, bob_handle_epoch, bob_handle_probe,
                                  open_sealed)
from crypto.identity import load_identity, load_peer                 # noqa: E402
from network.messages import MessageType                             # noqa: E402
from network.protocol import ProtocolError, Session                  # noqa: E402
from network.server import Server                                    # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Bob - hybrid QKD/PQC receiver")
    ap.add_argument("--host", default=config.BOB_HOST)
    ap.add_argument("--port", type=int, default=config.BOB_PORT)
    ap.add_argument("--channel-host", default=config.CHANNEL_HOST)
    ap.add_argument("--channel-port", type=int, default=config.CHANNEL_PORT)
    ap.add_argument("--min-gear", type=int, default=config.MIN_GEAR, choices=(1, 2, 3))
    ap.add_argument("--no-pqc", action="store_true", help="Bob has no post-quantum support")
    a = ap.parse_args()

    print("=" * 64)
    print("BOB")
    print("=" * 64)

    ctx = NodeContext(role="bob", identity=load_identity("bob"), peer=load_peer("alice"),
                      gears=GearController("bob", a.min_gear),
                      channel_addr=(a.channel_host, a.channel_port),
                      pqc_enabled=not a.no_pqc)

    server = Server(a.host, a.port)
    server.start()
    session = Session(server.connection)

    key = None
    last_seq = 0
    try:
        while True:
            packet = session.recv()
            kind = packet["type"]

            if kind == MessageType.EPOCH_START.value:
                epoch = packet["payload"].get("epoch")
                print(f"\n[EPOCH {epoch}] Alice requested new keys ...")
                key, last_seq = None, 0
                try:
                    key = bob_handle_epoch(session, ctx, packet)
                    print(f"[BOB] ready - key fingerprint {key.fingerprint}")
                except (EpochAborted, ProtocolError) as exc:
                    print(f"[EPOCH {epoch}] ABORTED: {exc}")
                except AuthenticationError as exc:
                    print(f"[SECURITY] {exc}. Closing the connection.")
                    break

            elif kind == MessageType.QBER_PROBE.value:
                bob_handle_probe(session, ctx, packet)     # measure probe photons, reply

            elif kind == MessageType.ENCRYPTED_MESSAGE.value:
                p = packet["payload"]
                if key is None:
                    print("[BOB] encrypted message received but no valid key - dropped")
                    continue
                if int(p["seq"]) <= last_seq:
                    print(f"[SECURITY] replayed/out-of-order message #{p['seq']} dropped")
                    continue
                try:
                    text = open_sealed(key, p)
                except (InvalidTag, ValueError) as exc:
                    print(f"[SECURITY] message rejected ({type(exc).__name__}: {exc})")
                    continue
                last_seq = int(p["seq"])
                print(f"\n[ALICE says | epoch {key.epoch} | Gear {key.gear} | #{last_seq}] {text}")

            elif kind == MessageType.CLOSE.value:
                print("\n[BOB] Alice closed the session.")
                break
    except ConnectionError:
        print("\n[BOB] connection lost.")
    finally:
        server.close()
        print("\n" + ctx.gears.summary())


if __name__ == "__main__":
    main()
