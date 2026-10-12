"""
controller/gear_controller.py

The 3-gear adaptive model.

    GEAR 3  QKD + ML-KEM + AES     QKD key accepted AND both sides have PQC
    GEAR 2  ML-KEM + ML-DSA + AES  QKD failed (QBER > 11%, link down,
                                   too little secret key) but PQC works
    GEAR 1  ECDH + AES             no QKD and no PQC - classical only,
                                   logged as a documented quantum risk

The decision is a pure function of facts BOTH nodes observed during the
handshake, so Alice and Bob compute it independently and must agree.
A mismatch means someone tampered with the handshake and the epoch is
aborted.

The controller is re-evaluated at every epoch, so the link can step
down (3 -> 2 -> 1) when the channel degrades and step back up when it
recovers.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from controller import config

SUITES = {
    3: "QKD + ML-KEM-768 + AES-256-GCM  (auth: ML-DSA-65)",
    2: "ML-KEM-768 + ML-DSA-65 + AES-256-GCM",
    1: "X25519 ECDH + AES-256-GCM  (auth: Ed25519)",
}
SECURITY = {
    3: "Hybrid: key stays secret unless BOTH QKD and ML-KEM are broken",
    2: "Post-quantum (ML-KEM-768)",
    1: "Classical only - DOCUMENTED QUANTUM RISK",
}


@dataclass
class Observations:
    """What one epoch's handshake established."""
    qkd_attempted: bool = False
    qber: Optional[float] = None
    qkd_key_bits: int = 0
    pqc_local: bool = False
    pqc_peer: bool = False
    reasons: List[str] = field(default_factory=list)

    @property
    def pqc_ok(self) -> bool:
        return self.pqc_local and self.pqc_peer

    @property
    def qkd_ok(self) -> bool:
        return self.qkd_key_bits >= config.MIN_QKD_KEY_BITS


def qber_acceptable(qber: float) -> bool:
    """Trigger: QBER above the BB84 bound means noise or an eavesdropper."""
    return qber <= config.QBER_THRESHOLD


def select_gear(obs: Observations) -> int:
    if obs.qkd_ok and obs.pqc_ok:
        return 3
    if obs.pqc_ok:
        return 2
    return 1


@dataclass
class GearRecord:
    epoch: int
    gear: int
    qber: Optional[float]
    reasons: List[str]
    time: str


class GearController:
    def __init__(self, role: str, min_gear: int = config.MIN_GEAR):
        self.role = role
        self.min_gear = min_gear
        self.current: Optional[int] = None
        self.history: List[GearRecord] = []

    def decide(self, obs: Observations) -> int:
        return select_gear(obs)

    def permitted(self, gear: int) -> bool:
        return gear >= self.min_gear

    def commit(self, epoch: int, gear: int, obs: Observations) -> None:
        previous = self.current
        self.current = gear
        self.history.append(GearRecord(epoch, gear, obs.qber, list(obs.reasons),
                                       datetime.now().strftime("%H:%M:%S")))
        self._announce(previous, gear, epoch, obs)

    # ------------------------------------------------------------------
    def _announce(self, previous, gear, epoch, obs):
        bar = "=" * 64
        print(f"\n{bar}")
        if previous is None:
            print(f"[GEAR] Epoch {epoch}: starting in GEAR {gear}")
        elif previous == gear:
            print(f"[GEAR] Epoch {epoch}: holding GEAR {gear}")
        else:
            arrow = "DOWNSHIFT" if gear < previous else "UPSHIFT"
            print(f"[GEAR] Epoch {epoch}: {arrow}  GEAR {previous} -> GEAR {gear}")
        print(f"       Suite    : {SUITES[gear]}")
        print(f"       Security : {SECURITY[gear]}")
        if obs.qber is not None:
            flag = "OK" if qber_acceptable(obs.qber) else f"> {config.QBER_THRESHOLD:.0%} threshold"
            print(f"       QBER     : {obs.qber:.2%} ({flag})")
        if obs.qkd_key_bits and gear == 3:
            print(f"       QKD key  : {obs.qkd_key_bits} secret bits after privacy amplification")
        elif obs.qkd_key_bits:
            print(f"       QKD key  : {obs.qkd_key_bits} bits distilled but NOT used "
                  f"(Gear {gear} policy: {SUITES[gear].split('  ')[0]} only)")
        for r in obs.reasons:
            print(f"       Trigger  : {r}")
        if gear == 1:
            print("       WARNING  : Gear 1 is breakable by a future quantum computer "
                  "(harvest-now-decrypt-later).")
        print(bar)

    def summary(self) -> str:
        lines = [f"{'epoch':>5}  {'time':8}  gear  {'QBER':>7}  trigger"]
        for h in self.history:
            q = f"{h.qber:.2%}" if h.qber is not None else "-"
            lines.append(f"{h.epoch:>5}  {h.time:8}  {h.gear:>4}  {q:>7}  "
                         f"{'; '.join(h.reasons) or 'all channels healthy'}")
        return "\n".join(lines)
