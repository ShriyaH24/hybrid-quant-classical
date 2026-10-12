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
import struct
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
    """A socket plus an optional running transcript hash."""

    def __init__(self, sock):
        self.sock = sock
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
    def send(self, message_type, payload: Optional[dict] = None) -> None:
        raw = encode_packet(message_type, payload)
        if self._transcript is not None:
            self._transcript.update(raw)
        self.sock.sendall(struct.pack(">I", len(raw)) + raw)

    def recv(self, *expected: MessageType) -> dict:
        raw = read_frame(self.sock)
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

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
