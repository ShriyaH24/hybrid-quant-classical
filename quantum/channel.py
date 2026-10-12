"""
quantum/channel.py

The simulated quantum channel between Alice and Bob.

  Alice prepares  ->  [ Eve? ]  ->  [ noise ]  ->  Bob measures

* noise: a depolarizing channel applied ONCE per photon, in the channel.
  It treats every state equally, so the error rate does not depend on
  which bit/basis Alice used. `noise` is the target bit-error rate:
  depolarizing strength lambda = 2 * noise.
* Eve: intercept-resend. She measures each photon in a random basis and
  re-sends what she saw. Wrong-basis guesses (50%) randomise Bob's
  result half the time -> ~25% QBER on the sifted key.
* link_up = False models a broken fibre / lost synchronisation.
"""

import secrets
from dataclasses import dataclass, field
from typing import List, Sequence, Tuple

from qiskit_aer.noise import depolarizing_error

from quantum.decoder import measure_all
from quantum.encoder import prepare_qubit


class QuantumLinkError(Exception):
    """The quantum channel cannot deliver photons right now."""


@dataclass
class ChannelStats:
    photons: int = 0
    eve_active: bool = False
    eve_basis_matches: int = 0
    sifted: int = 0
    sifted_errors: int = 0

    @property
    def true_qber(self) -> float:
        return self.sifted_errors / self.sifted if self.sifted else 0.0


@dataclass
class QuantumChannel:
    noise: float = 0.02
    eve: bool = False
    link_up: bool = True
    last_stats: ChannelStats = field(default_factory=ChannelStats)

    def transmit(self,
                 alice_bits: Sequence[int],
                 alice_bases: Sequence[int],
                 bob_bases: Sequence[int]) -> Tuple[List[int], ChannelStats]:
        if not self.link_up:
            raise QuantumLinkError("quantum link is down")

        stats = ChannelStats(photons=len(alice_bits), eve_active=self.eve)
        photons = [prepare_qubit(b, B) for b, B in zip(alice_bits, alice_bases)]

        if self.eve:
            eve_bases = [secrets.randbits(1) for _ in photons]
            eve_bits = measure_all(photons, eve_bases)
            photons = [prepare_qubit(b, B) for b, B in zip(eve_bits, eve_bases)]
            stats.eve_basis_matches = sum(a == e for a, e in zip(alice_bases, eve_bases))

        lam = min(1.0, 2.0 * max(0.0, self.noise))
        if lam > 0:
            noise_op = depolarizing_error(lam, 1).to_instruction()
            for qc in photons:
                qc.append(noise_op, [0])

        bob_bits = measure_all(photons, bob_bases)

        for a, ab, bb, b in zip(alice_bits, alice_bases, bob_bases, bob_bits):
            if ab == bb:
                stats.sifted += 1
                stats.sifted_errors += a != b
        self.last_stats = stats
        return bob_bits, stats
