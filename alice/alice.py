"""
alice/alice.py

Alice: leads every key exchange (epoch) and the channel monitor, and chats
with Bob in both directions.

The monitor probes the quantum channel every few seconds and shifts gear
on its own when the QBER, the link or PQC availability changes.

Run (after the channel server and Bob):
    python alice/alice.py                                   # all on one machine
    python alice/alice.py --host <BOB_IP> --channel-host <EVE_IP>
    python alice/alice.py --host <EVE_IP> --port 5001 --channel-host <EVE_IP>
                                                            # classical link through Eve's tap

Commands at the prompt:
    <any text>      encrypt and send to Bob   (>text forces sending, e.g. >eve on)
    /pqc off|on     simulate post-quantum crypto failing / recovering here
    /status         gear history + last probe
    /quiet          toggle the per-probe monitor lines
    /rekey          force a new epoch now
    /quit
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from controller import config                                       # noqa: E402
from controller.gear_controller import GearController                # noqa: E402
from controller.handshake import (AuthenticationError, NodeContext,   # noqa: E402
                                  alice_run_epoch, peer_already_knows)
from controller.monitor import ChannelMonitor                        # noqa: E402
from controller.node import Node                                     # noqa: E402
from crypto.identity import load_identity, load_peer                 # noqa: E402
from network.client import Client                                    # noqa: E402
from network.messages import MessageType                             # noqa: E402

# text that is almost certainly meant for the channel (Eve) console, not a message for Bob
CHANNEL_COMMAND = re.compile(
    r"^(eve\s+(on|off)|link\s+(up|down)|noise\s+\S+|watch\s+(on|off)|tap\s+\S+|tamper\s+\S+|status|quit)$",
    re.IGNORECASE)


class AliceNode(Node):
    """Alice = Node + she starts every epoch."""

    def __init__(self, sock, ctx, rekey_every=config.REKEY_EVERY, out=print):
        super().__init__(sock, ctx, rekey_every, out)
        self.epoch = 0

    def rekey(self, why: str = "manual") -> bool:
        with self.lock:
            if self.closed.is_set():
                return False
            self.epoch += 1
            self.out(f"\n[EPOCH {self.epoch}] negotiating keys ({why}) ...")
            self.begin_epoch()
            self.session.drain()
            try:
                self.install(alice_run_epoch(self.session, self.ctx, self.epoch))
                return True
            except ConnectionError:
                raise
            except Exception as exc:                      # any failure: no key, keep the session
                self.session.end_transcript()
                tag = "SECURITY" if isinstance(exc, AuthenticationError) else f"EPOCH {self.epoch}"
                self.out(f"[{tag}] epoch aborted: {exc}. Messages are blocked until a new epoch succeeds.")
                if not peer_already_knows(exc):
                    try:
                        self.session.send(MessageType.EPOCH_ABORT,
                                          {"epoch": self.epoch, "reason": str(exc)}, transcript=False)
                    except OSError:
                        pass
                return False
            finally:
                self.out(self.prompt())

    def rotate_if_due(self) -> None:
        if self.rotation_due.is_set():
            self.rekey(f"{self.messages_this_epoch} messages exchanged - routine key rotation")


def main():
    ap = argparse.ArgumentParser(description="Alice - hybrid QKD/PQC node (epoch leader)")
    ap.add_argument("--host", default=config.BOB_HOST, help="Bob's address (or Eve's tap)")
    ap.add_argument("--port", type=int, default=config.BOB_PORT)
    ap.add_argument("--channel-host", default=config.CHANNEL_HOST, help="quantum channel (Eve's machine)")
    ap.add_argument("--channel-port", type=int, default=config.CHANNEL_PORT)
    ap.add_argument("--qubits", type=int, default=config.RAW_QUBITS)
    ap.add_argument("--probe-every", type=float, default=config.PROBE_INTERVAL,
                    help="seconds between QBER probes (0 = monitor off)")
    ap.add_argument("--rekey-every", type=int, default=config.REKEY_EVERY,
                    help="messages (both directions) per epoch before key rotation (0 = never)")
    ap.add_argument("--min-gear", type=int, default=config.MIN_GEAR, choices=(1, 2, 3))
    ap.add_argument("--no-pqc", action="store_true", help="start with PQC disabled")
    a = ap.parse_args()

    print("=" * 64)
    print("ALICE")
    print("=" * 64)

    ctx = NodeContext(role="alice", identity=load_identity("alice"), peer=load_peer("bob"),
                      gears=GearController("alice", a.min_gear),
                      channel_addr=(a.channel_host, a.channel_port),
                      pqc_enabled=not a.no_pqc, qubits=a.qubits)

    client = Client(a.host, a.port)
    client.connect()
    node = AliceNode(client.socket, ctx, a.rekey_every, out=lambda m: print(m, end="" if m.endswith("> ") else "\n", flush=True))
    node.start_reader()
    node.rekey("session start")

    monitor = None
    if a.probe_every > 0:
        monitor = ChannelMonitor(node.session, ctx, node.lock,
                                 current_gear=lambda: node.current.gear if node.current else None,
                                 rekey=node.rekey, interval=a.probe_every,
                                 report=lambda m: print(m + "\n" + node.prompt(), end="", flush=True),
                                 on_tick=node.rotate_if_due,
                                 alive=lambda: not node.closed.is_set())
        monitor.start()
        print(f"\n[MONITOR] probing the quantum channel every {a.probe_every:g}s "
              f"({config.PROBE_QUBITS} photons, all sacrificed)")
    print(__doc__.split("Commands at the prompt:")[1])

    try:
        while not node.closed.is_set():
            line = input(node.prompt()).strip()
            if node.closed.is_set():
                break
            if not line:
                continue
            if line.startswith(">"):
                node.send_text(line[1:].strip())
                node.rotate_if_due()
                continue
            if CHANNEL_COMMAND.match(line):
                print(f"[ALICE] '{line}' is a CHANNEL/EVE command - type it in the channel window.\n"
                      f"        (To really send it to Bob as a message, type: >{line})")
                continue
            if not line.startswith("/"):
                node.send_text(line)
                node.rotate_if_due()
                continue

            cmd = line.lower().split()
            if cmd[0] == "/quit":
                break
            elif cmd[0] == "/status":
                print(ctx.gears.summary())
                if monitor and monitor.last:
                    d = monitor.last
                    q = f"{d.probe.qber:.2%}" if d.probe.qber is not None else "--"
                    print(f"last probe: QBER {q} | {d.reason} | channel supports G{d.predicted}")
            elif cmd[0] == "/quiet" and monitor:
                monitor.verbose = not monitor.verbose
                print(f"[MONITOR] per-probe lines {'ON' if monitor.verbose else 'OFF'} "
                      f"(gear triggers are always shown)")
            elif cmd[0] == "/pqc" and len(cmd) == 2 and cmd[1] in ("on", "off"):
                ctx.pqc_enabled = cmd[1] == "on"
                print(f"[ALICE] post-quantum crypto {'ENABLED' if ctx.pqc_enabled else 'DISABLED (simulated failure)'}"
                      + (" - the monitor will react at the next probe" if monitor else " - use /rekey"))
            elif cmd[0] == "/rekey":
                node.rekey("manual /rekey")
            else:
                print("commands: /pqc on|off, /status, /quiet, /rekey, /quit")
    except (EOFError, KeyboardInterrupt, ConnectionError):
        pass
    finally:
        if monitor:
            monitor.stop()
        node.close()
        print("\n" + ctx.gears.summary())


if __name__ == "__main__":
    main()
