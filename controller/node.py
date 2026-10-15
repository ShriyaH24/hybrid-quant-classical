"""
controller/node.py

What Alice and Bob have in common: one TCP connection, two-way encrypted
chat, and the keys of the current (and previous) epoch.

Threads on each side
--------------------
  reader   owns the socket. Chat (ENCRYPTED_MESSAGE) is decrypted and shown
           right here; CLOSE ends the session; every other frame (handshake,
           probe, abort) goes into the session's inbox for whoever is running
           the protocol. Because chat never enters the inbox, a message from
           the peer can arrive in the middle of a key exchange without
           disturbing it.
  input    the person typing (main thread).
  protocol Alice: the monitor thread (probes + epochs).
           Bob:   a worker that answers epochs and probes.

One lock (`self.lock`) is held for a whole epoch and for every chat send,
so nobody sends a message while the keys are being replaced.

Keys
----
Each epoch has two traffic keys (Alice->Bob, Bob->Alice). The receiver also
keeps the PREVIOUS epoch's keys, so a message that was already in flight
when a new epoch finished still decrypts. Sequence numbers are per epoch
and per direction; a repeated or older number is rejected as a replay.
"""

import queue
import threading
from typing import Callable, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag

from controller import config
from controller.handshake import EpochKey, NodeContext, open_sealed, seal
from network.messages import MessageType as M
from network.protocol import ProtocolError, Session, decode_packet, read_frame


class Node:
    def __init__(self, sock, ctx: NodeContext, rekey_every: int = config.REKEY_EVERY,
                 out: Callable[[str], None] = print):
        self.ctx = ctx
        self.role, self.peer = ctx.role, ctx.peer_role
        self.session = Session(sock, inbox=queue.Queue())
        self.lock = threading.RLock()
        self.out = out
        self.rekey_every = rekey_every

        self.keys: Dict[int, EpochKey] = {}           # epoch -> keys (current + previous)
        self.current: Optional[EpochKey] = None
        self.seq_out = 0
        self.last_seq_in: Dict[int, int] = {}
        self.messages_this_epoch = 0
        self.rotation_due = threading.Event()
        self.closed = threading.Event()
        self.received: List[Tuple[int, int, str]] = []   # (epoch, gear, text) - for tests / history

    # ------------------------------------------------------------------ prompt
    def prompt(self) -> str:
        return f"{self.role} [G{self.current.gear}]> " if self.current else f"{self.role} [no key]> "

    def say(self, line: str) -> None:
        """Print something that arrived asynchronously, then redraw the prompt."""
        self.out(f"\n{line}\n{self.prompt()}")

    # ------------------------------------------------------------------ reader
    def start_reader(self) -> "Node":
        threading.Thread(target=self._reader, daemon=True, name=f"{self.role}-reader").start()
        return self

    def _reader(self) -> None:
        try:
            while not self.closed.is_set():
                raw = read_frame(self.session.sock)
                packet = decode_packet(raw)
                kind = packet["type"]
                if kind == M.ENCRYPTED_MESSAGE.value:
                    self._on_message(packet["payload"])
                elif kind == M.CLOSE.value:
                    self.say(f"[{self.role.upper()}] {self.peer.capitalize()} closed the session.")
                    break
                else:
                    self.session.inbox.put(raw)
        except (ConnectionError, OSError, ProtocolError, ValueError) as exc:
            if not self.closed.is_set():
                self.say(f"[{self.role.upper()}] connection lost ({exc}).")
        finally:
            self.closed.set()
            self.session.inbox.put(None)            # wake anyone waiting for a handshake reply

    def _on_message(self, payload: dict) -> None:
        try:
            epoch, seq = int(payload["epoch"]), int(payload["seq"])
        except (KeyError, TypeError, ValueError):
            self.say("[SECURITY] malformed message dropped")
            return
        k = self.keys.get(epoch)
        if k is None:
            self.say(f"[SECURITY] message for unknown or expired epoch {epoch} dropped")
            return
        if seq <= self.last_seq_in.get(epoch, 0):
            self.say(f"[SECURITY] replayed or out-of-order message #{seq} (epoch {epoch}) dropped")
            return
        try:
            text = open_sealed(k, payload, expected_sender=self.peer)
        except (InvalidTag, ValueError) as exc:
            self.say(f"[SECURITY] message rejected - tampered or forged ({type(exc).__name__}"
                     f"{': ' + str(exc) if str(exc) else ''})")
            return
        self.last_seq_in[epoch] = seq
        self.received.append((epoch, k.gear, text))
        self.say(f"[{self.peer.upper()} says | epoch {epoch} | Gear {k.gear} | #{seq}] {text}")
        self._count_message()

    # ------------------------------------------------------------------ keys
    def begin_epoch(self) -> None:
        """A new key exchange is starting: stop sending under the old keys."""
        self.current = None
        self.seq_out = 0

    def install(self, k: EpochKey) -> None:
        self.keys[k.epoch] = k
        for old in [e for e in self.keys if e < k.epoch - 1]:   # keep current + previous
            del self.keys[old]
            self.last_seq_in.pop(old, None)
        self.current = k
        self.seq_out = 0
        self.messages_this_epoch = 0
        self.rotation_due.clear()

    def _count_message(self) -> None:
        self.messages_this_epoch += 1
        if self.rekey_every and self.messages_this_epoch >= self.rekey_every:
            self.rotation_due.set()

    # ------------------------------------------------------------------ chat
    def send_text(self, text: str) -> bool:
        with self.lock:
            k = self.current
            if k is None:
                self.out("[no valid key yet - a new key exchange is on its way]")
                return False
            self.seq_out += 1
            self.session.send(M.ENCRYPTED_MESSAGE, seal(k, self.role, self.seq_out, text), transcript=False)
            self.out(f"[SENT] epoch {k.epoch}, msg {self.seq_out}, Gear {k.gear}, key fp {k.fingerprint}")
            self._count_message()
            return True

    def close(self) -> None:
        with self.lock:
            if not self.closed.is_set():
                try:
                    self.session.send(M.CLOSE, {}, transcript=False)
                except OSError:
                    pass
            self.closed.set()
            self.session.close()
