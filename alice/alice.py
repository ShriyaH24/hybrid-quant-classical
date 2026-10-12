"""
alice/alice.py

Alice: initiates key-establishment epochs and sends encrypted messages.

A background MONITOR probes the quantum channel every few seconds and
shifts gear on its own when the QBER, the link or PQC availability
changes - no typing needed. Watch it react to `eve on`, `noise 0.06`
or `link down` in the channel console.

Run (after the channel server and Bob):
    python alice/alice.py
    python alice/alice.py --probe-every 3      # probe faster
    python alice/alice.py --probe-every 0      # monitor off (manual /rekey only)

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
import threading

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from controller import config                                       # noqa: E402
from controller.gear_controller import GearController                # noqa: E402
from controller.handshake import (AuthenticationError, EpochAborted,  # noqa: E402
                                  NodeContext, alice_run_epoch, seal)
from controller.monitor import ChannelMonitor                        # noqa: E402
from crypto.identity import load_identity, load_peer                 # noqa: E402
from network.client import Client                                    # noqa: E402
from network.messages import MessageType                             # noqa: E402
from network.protocol import ProtocolError, Session                  # noqa: E402


# text that is almost certainly meant for the channel console, not a message for Bob
CHANNEL_COMMAND = re.compile(r"^(eve\s+(on|off)|link\s+(up|down)|noise\s+\S+|watch\s+(on|off)|status|quit)$",
                             re.IGNORECASE)


class AliceNode:
    """Holds the session and current key; one lock serialises all traffic."""

    def __init__(self, session: Session, ctx: NodeContext, rekey_every: int):
        self.session, self.ctx = session, ctx
        self.rekey_every = rekey_every
        self.lock = threading.RLock()
        self.epoch = 0
        self.key = None
        self.seq = 0
        self.sent_in_epoch = 0

    def prompt(self) -> str:
        return f"alice [G{self.key.gear}]> " if self.key else "alice [no key]> "

    def rekey(self, why: str = "manual") -> None:
        with self.lock:
            self.epoch += 1
            print(f"\n[EPOCH {self.epoch}] negotiating keys ({why}) ...", flush=True)
            self.key, self.seq, self.sent_in_epoch = None, 0, 0
            try:
                self.key = alice_run_epoch(self.session, self.ctx, self.epoch)
            except (EpochAborted, ProtocolError) as exc:
                print(f"[EPOCH {self.epoch}] ABORTED: {exc}. Messages are blocked until a new epoch succeeds.")
            except AuthenticationError as exc:
                print(f"[SECURITY] {exc}. Closing the connection.")
                os._exit(1)
            print(self.prompt(), end="", flush=True)

    def send(self, text: str) -> None:
        with self.lock:
            if self.key is None:
                print("[ALICE] no valid key yet - the monitor will retry, or use /rekey")
                return
            self.seq += 1
            self.session.send(MessageType.ENCRYPTED_MESSAGE, seal(self.key, self.seq, text))
            self.sent_in_epoch += 1
            print(f"[SENT] epoch {self.key.epoch}, msg {self.seq}, Gear {self.key.gear}, "
                  f"key fp {self.key.fingerprint}")
            if self.rekey_every and self.sent_in_epoch >= self.rekey_every:
                self.rekey(f"{self.sent_in_epoch} messages sent - routine key rotation")


def main():
    ap = argparse.ArgumentParser(description="Alice - hybrid QKD/PQC sender")
    ap.add_argument("--host", default=config.BOB_HOST)
    ap.add_argument("--port", type=int, default=config.BOB_PORT)
    ap.add_argument("--channel-host", default=config.CHANNEL_HOST)
    ap.add_argument("--channel-port", type=int, default=config.CHANNEL_PORT)
    ap.add_argument("--qubits", type=int, default=config.RAW_QUBITS)
    ap.add_argument("--probe-every", type=float, default=config.PROBE_INTERVAL,
                    help="seconds between QBER probes (0 = monitor off)")
    ap.add_argument("--rekey-every", type=int, default=config.REKEY_EVERY,
                    help="messages per epoch before routine key rotation (0 = never)")
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
    node = AliceNode(Session(client.socket), ctx, a.rekey_every)
    node.rekey("session start")

    monitor = None
    if a.probe_every > 0:
        monitor = ChannelMonitor(node.session, ctx, node.lock,
                                 current_gear=lambda: node.key.gear if node.key else None,
                                 rekey=node.rekey, interval=a.probe_every,
                                 report=lambda m: print(m + "\n" + node.prompt(), end="", flush=True))
        monitor.start()
        print(f"\n[MONITOR] probing the quantum channel every {a.probe_every:g}s "
              f"({config.PROBE_QUBITS} photons, all sacrificed)")
    print(__doc__.split("Commands at the prompt:")[1])

    try:
        while True:
            line = input(node.prompt()).strip()
            if not line:
                continue
            if line.startswith(">"):              # explicit: send this text as a message
                node.send(line[1:].strip())
                continue
            if CHANNEL_COMMAND.match(line):
                print(f"[ALICE] '{line}' is a CHANNEL command - type it in the quantum channel window.\n"
                      f"        (To really send it to Bob as a message, type: >{line})")
                continue
            if not line.startswith("/"):
                node.send(line)
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
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        if monitor:
            monitor.stop()
        with node.lock:
            try:
                node.session.send(MessageType.CLOSE, {})
            except OSError:
                pass
            client.close()
        print("\n" + ctx.gears.summary())


if __name__ == "__main__":
    main()