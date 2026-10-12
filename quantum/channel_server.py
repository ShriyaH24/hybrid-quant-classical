"""
quantum/channel_server.py

Runs the simulated quantum channel as its own process, with a console
to attack or break it while Alice and Bob are talking.

    python -m quantum.channel_server            # clean channel, 2% noise
    python -m quantum.channel_server --eve      # start with Eve listening

Console commands:
    eve on | eve off      intercept-resend eavesdropper
    noise <p>             channel bit-error rate, e.g. noise 0.05
    link down | link up   cut / restore the quantum link
    watch on | watch off  show / hide a line for every 5-second probe
    status                show current settings
    quit

Probe lines are hidden by default so they don't break up your typing;
full key-exchange (epoch) lines are always shown.
"""

import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from network.messages import MessageType                      # noqa: E402
from network.protocol import receive_packet, send_packet      # noqa: E402
from quantum.channel import QuantumChannel, QuantumLinkError  # noqa: E402

SESSION_TTL = 120   # seconds a batch of photons waits for Bob


class ChannelServer:
    def __init__(self, channel: QuantumChannel, host="127.0.0.1", port=6000, verbose=True):
        self.channel = channel
        self.host, self.port = host, port
        self.verbose = verbose
        self.show_probes = False     # probes arrive every few seconds - hidden by default
        self.interactive = False     # redraw the "channel> " prompt after log lines
        self.pending = {}            # sid -> (bits, bases, created)
        self.lock = threading.Lock()
        self._sock = None

    def log(self, msg):
        if self.verbose:
            prompt = "channel> " if self.interactive else ""
            print(f"\n[CHANNEL] {msg}\n{prompt}", end="", flush=True)

    # ---------------------------------------------------------
    def start(self) -> "ChannelServer":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(8)
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self

    def stop(self):
        if self._sock:
            self._sock.close()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            try:
                packet = receive_packet(conn)
                p = packet["payload"]
                if packet["type"] == MessageType.Q_SEND.value:
                    self._on_send(conn, p)
                elif packet["type"] == MessageType.Q_MEASURE.value:
                    self._on_measure(conn, p)
                else:
                    send_packet(conn, MessageType.Q_ERROR, {"reason": "unknown request"})
            except Exception as exc:                     # keep the server alive
                self.log(f"request failed: {exc}")
                try:
                    send_packet(conn, MessageType.Q_ERROR, {"reason": str(exc)})
                except OSError:
                    pass

    def _on_send(self, conn, p):
        if not self.channel.link_up:
            self.log("Alice tried to send photons, but the quantum link is DOWN")
            send_packet(conn, MessageType.Q_ERROR, {"reason": "quantum link is down"})
            return
        with self.lock:
            now = time.time()
            self.pending = {k: v for k, v in self.pending.items() if now - v[2] < SESSION_TTL}
            self.pending[p["sid"]] = (p["bits"], p["bases"], now)
        send_packet(conn, MessageType.Q_SEND_ACK, {})

    def _on_measure(self, conn, p):
        with self.lock:
            entry = self.pending.pop(p["sid"], None)   # photons can only be measured once
        if entry is None:
            send_packet(conn, MessageType.Q_ERROR, {"reason": "no photons for this session"})
            return
        bits, bases, _ = entry
        try:
            bob_bits, st = self.channel.transmit(bits, bases, p["bases"])
        except QuantumLinkError as exc:
            self.log(f"photons lost in transit: {exc}")
            send_packet(conn, MessageType.Q_ERROR, {"reason": str(exc)})
            return
        eve = " | EVE INTERCEPTED every photon" if st.eve_active else ""
        kind = "probe" if st.photons <= 2048 else "epoch"
        if kind == "epoch" or self.show_probes:
            self.log(f"{kind}: {st.photons} photons | true sifted error rate "
                     f"{st.true_qber:.2%} (noise setting {self.channel.noise:.2%}){eve}")
        send_packet(conn, MessageType.Q_RESULT, {"bits": bob_bits})

    # ---------------------------------------------------------
    def status(self) -> str:
        c = self.channel
        return (f"link={'UP' if c.link_up else 'DOWN'}  noise={c.noise:.2%}  "
                f"eve={'ON' if c.eve else 'off'}  listening on {self.host}:{self.port}")


def console(server: ChannelServer):
    print(__doc__.split("Console commands:")[1])
    print(f"[CHANNEL] {server.status()}")
    server.interactive = True
    ch = server.channel
    while True:
        try:
            cmd = input("channel> ").strip().lower().split()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        if cmd[0].startswith("/"):
            print(f"'{' '.join(cmd)}' is an ALICE command - type it in Alice's window.")
            continue
        if cmd[0] in ("quit", "exit"):
            break
        elif cmd == ["eve", "on"]:
            ch.eve = True
        elif cmd == ["eve", "off"]:
            ch.eve = False
        elif cmd == ["link", "down"]:
            ch.link_up = False
        elif cmd == ["link", "up"]:
            ch.link_up = True
        elif cmd == ["watch", "on"]:
            server.show_probes = True
        elif cmd == ["watch", "off"]:
            server.show_probes = False
        elif cmd[0] == "noise" and len(cmd) == 2:
            try:
                value = float(cmd[1].rstrip("%"))
            except ValueError:
                print("usage: noise 0.03   (or: noise 3%)")
                continue
            if cmd[1].endswith("%") or value > 0.5:     # accept "3" or "3%" as percent
                value /= 100
            ch.noise = min(0.5, max(0.0, value))
        elif cmd[0] != "status":
            print("commands: eve on|off, noise <p>, link up|down, watch on|off, status, quit")
            continue
        print(f"[CHANNEL] {server.status()}  probes={'shown' if server.show_probes else 'hidden'}")


def main():
    ap = argparse.ArgumentParser(description="Simulated BB84 quantum channel")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--noise", type=float, default=0.02, help="bit-error rate of the channel")
    ap.add_argument("--eve", action="store_true", help="start with the eavesdropper active")
    ap.add_argument("--link-down", action="store_true", help="start with the link broken")
    a = ap.parse_args()

    print("=" * 60)
    print("QUANTUM CHANNEL (simulated with Qiskit Aer)")
    print("=" * 60)
    channel = QuantumChannel(noise=a.noise, eve=a.eve, link_up=not a.link_down)
    server = ChannelServer(channel, a.host, a.port).start()
    console(server)
    server.stop()


if __name__ == "__main__":
    main()
