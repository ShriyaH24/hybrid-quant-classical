"""
quantum/client.py

How Alice and Bob reach the quantum channel server.

Alice only ever sends her bits/bases to the CHANNEL (her photon source),
never to Bob. Bob only gets back his own measurement results.
"""

import socket
from typing import List, Sequence, Tuple

from network.messages import MessageType
from network.protocol import receive_packet, send_packet
from quantum.channel import QuantumLinkError

TIMEOUT = 60


def _call(addr: Tuple[str, int], mtype: MessageType, payload: dict) -> dict:
    try:
        with socket.create_connection(addr, timeout=TIMEOUT) as sock:
            send_packet(sock, mtype, payload)
            reply = receive_packet(sock)
    except OSError as exc:
        raise QuantumLinkError(f"channel server unreachable at {addr[0]}:{addr[1]} ({exc})")
    if reply["type"] == MessageType.Q_ERROR.value:
        raise QuantumLinkError(reply["payload"].get("reason", "unknown error"))
    return reply["payload"]


def send_photons(addr, session_id: str, bits: Sequence[int], bases: Sequence[int]) -> None:
    _call(addr, MessageType.Q_SEND, {"sid": session_id, "bits": list(bits), "bases": list(bases)})


def measure_photons(addr, session_id: str, bases: Sequence[int]) -> List[int]:
    return _call(addr, MessageType.Q_MEASURE, {"sid": session_id, "bases": list(bases)})["bits"]
