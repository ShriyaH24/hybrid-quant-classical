"""
network/protocol.py

Length-prefixed JSON packets over TCP:

    [4-byte big-endian length][JSON {"type": ..., "payload": {...}}]

`Session` wraps a socket and keeps a running SHA-256 of every packet
sent and received during a key-establishment epoch. Both sides end up
with the same transcript hash, and signing it authenticates the whole
handshake: if anyone changed a single byte in transit (e.g. stripped
"pqc": true to force a downgrade), the signatures fail.
"""

import hashlib
import json
import queue
import struct
import threading
from typing import Optional

from network.messages import MessageType

MAX_PACKET_BYTES = 8 * 1024 * 1024    # refuse absurd lengths instead of allocating them


class ProtocolError(Exception):
    pass


def _type_value(message_type) -> str:
    return message_type.value if isinstance(message_type, MessageType) else str(message_type)


def encode_packet(message_type, payload: Optional[dict] = None) -> bytes:
    packet = {"type": _type_value(message_type), "payload": payload or {}}
    return json.dumps(packet, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _recv_exact(sock, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed by peer.")
        data += chunk
    return bytes(data)


def read_frame(sock) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > MAX_PACKET_BYTES:
        raise ProtocolError(f"Packet of {length} bytes exceeds limit")
    return _recv_exact(sock, length)


def decode_packet(raw: bytes) -> dict:
    packet = json.loads(raw.decode("utf-8"))
    if not (isinstance(packet, dict) and isinstance(packet.get("type"), str)
            and isinstance(packet.get("payload"), dict)):
        raise ProtocolError("Malformed packet")
    return packet


def send_packet(sock, message_type, payload: Optional[dict] = None) -> None:
    raw = encode_packet(message_type, payload)
    sock.sendall(struct.pack(">I", len(raw)) + raw)


def receive_packet(sock) -> dict:
    return decode_packet(read_frame(sock))


class Session:
    """
    A socket plus an optional running transcript hash.

    Two ways to receive:
      * direct  - recv() reads the socket itself (single-threaded use, tests)
      * inbox   - a background reader (controller/node.py) owns the socket,
                  handles chat itself and puts every handshake/probe frame
                  into `inbox`; recv() then takes frames from the queue.
    Sends are serialised by a lock, so chat from one thread and handshake
    traffic from another never interleave inside a frame.
    """

    def __init__(self, sock, inbox: Optional["queue.Queue"] = None):
        self.sock = sock
        self.inbox = inbox
        self._send_lock = threading.Lock()
        self._transcript = None
        self._last_raw = b""
        self.hash_before_last_recv = b""

    # -- transcript --------------------------------------------
    def begin_transcript(self, include_last_received: bool = False) -> None:
        self._transcript = hashlib.sha256(b"HCQC-transcript-v1")
        if include_last_received:
            self._transcript.update(self._last_raw)

    def transcript_hash(self) -> bytes:
        return self._transcript.copy().digest() if self._transcript is not None else b""

    def end_transcript(self) -> None:
        self._transcript = None

    # -- I/O ----------------------------------------------------
    def send(self, message_type, payload: Optional[dict] = None, transcript: bool = True) -> None:
        """transcript=False for chat/close: never part of a handshake hash."""
        raw = encode_packet(message_type, payload)
        if transcript and self._transcript is not None:
            self._transcript.update(raw)
        with self._send_lock:
            self.sock.sendall(struct.pack(">I", len(raw)) + raw)

    def _next_raw(self, timeout: Optional[float]) -> bytes:
        if self.inbox is None:
            return read_frame(self.sock)
        try:
            raw = self.inbox.get(timeout=timeout)
        except queue.Empty:
            raise ProtocolError(f"no reply from peer within {timeout:.0f}s")
        if raw is None:                                    # reader saw the connection close
            self.inbox.put(None)                           # keep the signal for other waiters
            raise ConnectionError("Connection closed by peer.")
        return raw

    def recv(self, *expected: MessageType, timeout: Optional[float] = 60.0) -> dict:
        raw = self._next_raw(timeout)
        self.hash_before_last_recv = self.transcript_hash()
        if self._transcript is not None:
            self._transcript.update(raw)
        self._last_raw = raw
        packet = decode_packet(raw)
        if expected and packet["type"] not in {e.value for e in expected}:
            if packet["type"] == MessageType.EPOCH_ABORT.value:
                raise ProtocolError(f"Peer aborted epoch: {packet['payload'].get('reason')}")
            raise ProtocolError(
                f"Expected {'/'.join(e.value for e in expected)}, got {packet['type']}")
        return packet

    def drain(self) -> int:
        """Throw away stale handshake frames left over from an aborted epoch."""
        dropped = 0
        while self.inbox is not None:
            try:
                raw = self.inbox.get_nowait()
            except queue.Empty:
                break
            if raw is None:
                self.inbox.put(None)
                break
            dropped += 1
        return dropped

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
