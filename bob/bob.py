"""
bob/bob.py

Bob: answers every key exchange and channel probe Alice starts, and chats
with Alice in both directions.

Run (after the channel server, before Alice):
    python bob/bob.py                                        # all on one machine
    python bob/bob.py --host 0.0.0.0 --channel-host <EVE_IP> # on his own machine
    python bob/bob.py --no-pqc       # Bob has no post-quantum support
    python bob/bob.py --min-gear 2   # refuse quantum-vulnerable Gear 1

Commands at the prompt:
    <any text>      encrypt and send to Alice
    /status         gear history
    /quit
"""

import argparse
import os
import sys
import threading

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from controller import config                                       # noqa: E402
from controller.gear_controller import GearController                # noqa: E402
from controller.handshake import (AuthenticationError, NodeContext,   # noqa: E402
                                  bob_handle_epoch, bob_handle_probe, peer_already_knows)
from controller.node import Node                                     # noqa: E402
from crypto.identity import load_identity, load_peer                 # noqa: E402
from network.messages import MessageType as M                        # noqa: E402
from network.protocol import ProtocolError                           # noqa: E402
from network.server import Server                                    # noqa: E402


class BobNode(Node):
    """Bob = Node + a worker that answers Alice's epochs and probes."""

    def start_worker(self) -> "BobNode":
        threading.Thread(target=self._worker, daemon=True, name="bob-worker").start()
        return self

    def _worker(self) -> None:
        while not self.closed.is_set():
            try:
                packet = self.session.recv(timeout=None)
            except ConnectionError:
                return
            except (ProtocolError, ValueError):
                continue
            kind = packet["type"]
            if kind == M.EPOCH_START.value:
                self._epoch(packet)
            elif kind == M.QBER_PROBE.value:
                try:
                    bob_handle_probe(self.session, self.ctx, packet)
                except (ConnectionError, OSError):
                    return
                except Exception as exc:
                    self.say(f"[BOB] probe failed: {exc}")
            elif kind == M.EPOCH_ABORT.value:
                self._peer_aborted(packet["payload"])
            # anything else is a stale frame from an aborted exchange: ignore it

    def _epoch(self, packet: dict) -> None:
        epoch = packet["payload"].get("epoch")
        with self.lock:
            self.out(f"\n[EPOCH {epoch}] Alice requested new keys ...")
            self.begin_epoch()
            try:
                k = bob_handle_epoch(self.session, self.ctx, packet)
                self.install(k)
                self.out(f"[BOB] ready - key fingerprint {k.fingerprint}")
            except (ConnectionError, OSError):
                return
            except Exception as exc:                      # any failure: no key, keep the session
                self.session.end_transcript()
                tag = "SECURITY" if isinstance(exc, AuthenticationError) else f"EPOCH {epoch}"
                self.out(f"[{tag}] epoch aborted: {exc}")
                if not peer_already_knows(exc):
                    try:
                        self.session.send(M.EPOCH_ABORT, {"epoch": epoch, "reason": str(exc)}, transcript=False)
                    except OSError:
                        pass
            finally:
                self.out(self.prompt())

    def _peer_aborted(self, payload: dict) -> None:
        """Alice rejected an epoch we had finished (e.g. our confirmation failed
        to verify on her side): throw those keys away."""
        with self.lock:
            epoch = payload.get("epoch")
            if self.current is not None and self.current.epoch == epoch:
                self.keys.pop(epoch, None)
                self.current = None
            self.say(f"[EPOCH {epoch}] Alice aborted it: {payload.get('reason')} - keys discarded")


def main():
    ap = argparse.ArgumentParser(description="Bob - hybrid QKD/PQC node (responder)")
    ap.add_argument("--host", default=config.BOB_HOST, help="address to listen on (0.0.0.0 = all networks)")
    ap.add_argument("--port", type=int, default=config.BOB_PORT)
    ap.add_argument("--channel-host", default=config.CHANNEL_HOST, help="quantum channel (Eve's machine)")
    ap.add_argument("--channel-port", type=int, default=config.CHANNEL_PORT)
    ap.add_argument("--rekey-every", type=int, default=config.REKEY_EVERY)
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
    node = BobNode(server.connection, ctx, a.rekey_every,
                   out=lambda m: print(m, end="" if m.endswith("> ") else "\n", flush=True))
    node.start_reader().start_worker()
    print(__doc__.split("Commands at the prompt:")[1])

    try:
        while not node.closed.is_set():
            line = input(node.prompt()).strip()
            if node.closed.is_set():
                break
            if not line:
                continue
            if line.lower() == "/quit":
                break
            if line.lower() == "/status":
                print(ctx.gears.summary())
                continue
            if line.startswith("/"):
                print("commands: /status, /quit  (key exchanges are started by Alice)")
                continue
            node.send_text(line[1:].strip() if line.startswith(">") else line)
    except (EOFError, KeyboardInterrupt, ConnectionError):
        pass
    finally:
        node.close()
        server.close()
        print("\n" + ctx.gears.summary())


if __name__ == "__main__":
    main()
