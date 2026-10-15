"""
network/relay.py

Eve's tap on the CLASSICAL link: Alice connects to Eve, Eve connects to Bob,
and every frame passes through her machine.

What it demonstrates
  * passive: Eve sees every packet - but chat is AES-GCM ciphertext and the
    handshake carries only public values, so she learns no key or message.
  * active:  Eve can flip one character in the next chat message or the next
    handshake packet. A tampered message fails its GCM tag and is rejected;
    a tampered handshake changes one side's transcript, the signatures no
    longer verify, and neither side gets a key from that epoch.

Frames are forwarded byte for byte; only a deliberately tampered frame is
re-encoded (with the same canonical JSON encoding the protocol uses).
"""

import json
import socket
import struct
import threading
from typing import Callable, Optional

from network.protocol import encode_packet, read_frame

CHAT = "ENCRYPTED_MESSAGE"
PROBES = {"QBER_PROBE", "PROBE_REPLY"}
HANDSHAKE = {"EPOCH_ACK", "QKD_SIFT", "QKD_SAMPLE", "RECON_START", "PARITY_REQUEST",
             "PARITY_RESPONSE", "RECON_DONE", "PRIVACY_SEED", "KEM_CIPHERTEXT",
             "GEAR_COMMIT", "GEAR_CONFIRM", "EPOCH_START"}


def _flip_first_hex_field(payload: dict) -> Optional[str]:
    """Change one character of the first long hex string; returns the field name."""
    for key in ("ct", "sig", "mac", "seed", "nonce", "x25519", "kem_pk", "tag", "sid"):
        v = payload.get(key)
        if isinstance(v, str) and len(v) >= 8 and all(c in "0123456789abcdef" for c in v):
            i = len(v) // 2
            payload[key] = v[:i] + ("0" if v[i] != "0" else "1") + v[i + 1:]
            return key
    return None


class ClassicalTap:
    def __init__(self, listen_host: str, listen_port: int, bob_host: str, bob_port: int,
                 log: Callable[[str], None] = print):
        self.listen_addr = (listen_host, listen_port)
        self.bob_addr = (bob_host, bob_port)
        self.log = log
        self.mode = "on"                # off | on (chat only) | all (every packet)
        self.tamper: Optional[str] = None   # None | "message" | "handshake"
        self.counts = {"alice->bob": 0, "bob->alice": 0}
        self._sock = None

    # ------------------------------------------------------------------
    def start(self) -> "ClassicalTap":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(self.listen_addr)
        self.listen_addr = (self.listen_addr[0], self._sock.getsockname()[1])
        self._sock.listen(4)
        threading.Thread(target=self._accept, daemon=True, name="eve-tap").start()
        return self

    def stop(self):
        if self._sock:
            self._sock.close()

    def _accept(self):
        """Keep accepting: a failed attempt (e.g. Bob not up yet) must not need an Eve restart."""
        while True:
            try:
                alice, addr = self._sock.accept()
            except OSError:
                return
            try:
                bob = socket.create_connection(self.bob_addr, timeout=10)
                bob.settimeout(None)
            except OSError as exc:
                self.log(f"[EVE] Alice connected from {addr[0]}, but Bob is unreachable at "
                         f"{self.bob_addr[0]}:{self.bob_addr[1]} ({exc}).\n"
                         f"      Check: Bob is running with --host 0.0.0.0, the IP after --tap-to is "
                         f"Bob's, and Bob's firewall allows port {self.bob_addr[1]}. Alice can simply retry.")
                alice.close()
                continue
            self.log(f"[EVE] tapping the classical link: Alice {addr[0]} <-> Eve <-> Bob {self.bob_addr[0]}")
            threading.Thread(target=self._pump, args=(alice, bob, "alice->bob"), daemon=True).start()
            threading.Thread(target=self._pump, args=(bob, alice, "bob->alice"), daemon=True).start()

    def _pump(self, src, dst, direction):
        try:
            while True:
                raw = read_frame(src)
                raw = self._inspect(raw, direction)
                dst.sendall(struct.pack(">I", len(raw)) + raw)
        except (ConnectionError, OSError, ValueError):
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass
            self.log(f"[EVE] classical link closed ({direction})")

    # ------------------------------------------------------------------
    def _inspect(self, raw: bytes, direction: str) -> bytes:
        self.counts[direction] += 1
        try:
            packet = json.loads(raw)
        except ValueError:
            return raw
        kind, p = packet.get("type"), packet.get("payload", {})

        if kind == CHAT and self.mode != "off":
            self.log(f"[EVE] intercepted {direction} message #{p.get('seq')} (epoch {p.get('epoch')}): "
                     f"{len(p.get('ct', '')) // 2} bytes of ciphertext {p.get('ct', '')[:24]}... - unreadable")
        elif self.mode == "all" and kind not in PROBES:
            self.log(f"[EVE] saw {direction} {kind}")

        target = ((self.tamper == "message" and kind == CHAT)
                  or (self.tamper == "handshake" and kind in HANDSHAKE))
        if target:
            field = _flip_first_hex_field(p)
            if field:
                self.tamper = None
                self.log(f"[EVE] TAMPERED with {direction} {kind} (changed one character of '{field}')")
                return encode_packet(kind, p)
        return raw

    def status(self) -> str:
        return (f"tap {self.listen_addr[0]}:{self.listen_addr[1]} -> Bob {self.bob_addr[0]}:{self.bob_addr[1]}"
                f"  mode={self.mode}  tamper={self.tamper or 'off'}  "
                f"frames a->b {self.counts['alice->bob']}, b->a {self.counts['bob->alice']}")
