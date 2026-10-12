"""
controller/monitor.py

Continuous QBER monitoring - the "Monitor QBER -> Threshold -> Trigger"
loop from the methodology.

Every PROBE_INTERVAL seconds Alice sends a small batch of probe photons
(all revealed, never used as key) and measures the channel. From that
reading the monitor PREDICTS which gear the channel can support right
now and compares it with the gear in use:

  predicted < current  ->  re-key immediately          (DOWNSHIFT, fail fast)
  predicted > current  ->  re-key after UPSHIFT_CONFIRMATIONS healthy
                           probes in a row              (UPSHIFT, no flapping)
  same                 ->  keep going

The probe only TRIGGERS a re-key. The actual gear is still decided inside
the full, signed epoch, from that epoch's own QBER sample.
"""

import math
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from controller import config
from controller.gear_controller import Observations, qber_acceptable, select_gear
from controller.handshake import NodeContext, ProbeResult, alice_probe
from crypto.privacy import binary_entropy, secret_key_length


def expected_qkd_key_bits(qber: float) -> int:
    """Secret bits a full epoch would likely yield at this QBER."""
    n_sifted = config.RAW_QUBITS // 2
    n_sample = int(n_sifted * config.SAMPLE_FRACTION)
    n_key = n_sifted - n_sample
    leak = int(math.ceil(config.EC_EFFICIENCY * n_key * binary_entropy(qber)))
    return secret_key_length(n_key, qber, n_sample, leak, config.VERIFY_TAG_BITS,
                             config.PA_EPSILON, config.PE_SIGMAS)[0]


def predict_gear(probe: ProbeResult, pqc_local: bool, pqc_peer: bool) -> (int, str):
    """Which gear a new epoch would land in, judging from one probe."""
    if not probe.link_ok:
        qkd_ok, why = False, f"quantum link failure ({probe.error or 'no photons'})"
    elif not qber_acceptable(probe.qber):
        qkd_ok, why = False, f"QBER {probe.qber:.2%} > {config.QBER_THRESHOLD:.0%} threshold"
    elif expected_qkd_key_bits(probe.qber) < config.MIN_QKD_KEY_BITS:
        qkd_ok, why = False, f"QBER {probe.qber:.2%} too high to distil a {config.MIN_QKD_KEY_BITS}-bit key"
    else:
        qkd_ok, why = True, f"QBER {probe.qber:.2%} healthy"
    if not pqc_local:
        why += "; PQC unavailable locally"
    obs = Observations(qkd_key_bits=config.MIN_QKD_KEY_BITS if qkd_ok else 0,
                       pqc_local=pqc_local, pqc_peer=pqc_peer)
    return select_gear(obs), why


@dataclass
class Decision:
    probe: ProbeResult
    predicted: int
    reason: str
    trigger: Optional[str] = None      # "DOWNSHIFT", "UPSHIFT", "RECOVER" or None


class ChannelMonitor:
    """
    check_once() does one probe + decision; start() runs it in a background
    thread. `rekey(reason)` is called when a transition is triggered.
    `lock` must be the same lock that guards every other use of the session.
    """

    def __init__(self, session, ctx: NodeContext, lock: threading.RLock,
                 current_gear: Callable[[], Optional[int]],
                 rekey: Callable[[str], None],
                 interval: float = config.PROBE_INTERVAL,
                 probe_qubits: int = config.PROBE_QUBITS,
                 confirmations: int = config.UPSHIFT_CONFIRMATIONS,
                 report: Callable[[str], None] = print):
        self.session, self.ctx, self.lock = session, ctx, lock
        self.current_gear, self.rekey = current_gear, rekey
        self.interval, self.probe_qubits, self.confirmations = interval, probe_qubits, confirmations
        self.report = report
        self.healthy_streak = 0
        self.last: Optional[Decision] = None
        self.verbose = True
        self._stop = threading.Event()
        self._thread = None

    def check_once(self) -> Decision:
        with self.lock:
            probe = alice_probe(self.session, self.ctx, self.probe_qubits)
            predicted, why = predict_gear(probe, self.ctx.pqc_capable, self.ctx.peer_pqc_last)
            current = self.current_gear()
            d = Decision(probe, predicted, why)

            if current is None:
                d.trigger = "RECOVER"                     # last epoch failed: try again
            elif predicted < current:
                d.trigger = "DOWNSHIFT"
                self.healthy_streak = 0
            elif predicted > current:
                self.healthy_streak += 1
                if self.healthy_streak >= self.confirmations:
                    d.trigger = "UPSHIFT"
                    self.healthy_streak = 0
            else:
                self.healthy_streak = 0

            self.last = d
            self._report(d, current)
            if d.trigger:
                self.rekey(f"monitor {d.trigger}: {why}")
            return d

    def _report(self, d: Decision, current):
        q = f"{d.probe.qber:6.2%}" if d.probe.qber is not None else "  --  "
        cur = f"G{current}" if current else "none"
        if d.trigger:
            self.report(f"\n[MONITOR] QBER {q} | {d.reason} -> {d.trigger} trigger "
                        f"(current {cur}, channel supports G{d.predicted}) - re-keying")
        elif self.verbose:
            pending = (f" | upshift to G{d.predicted} in "
                       f"{self.confirmations - self.healthy_streak} more healthy probe(s)"
                       if d.predicted > (current or 0) else "")
            self.report(f"\n[MONITOR] QBER {q} | {d.reason} | holding {cur}{pending}")

    # ---- background thread ----------------------------------------
    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self.interval):
            try:
                self.check_once()
            except Exception as exc:                        # connection closed etc.
                if not self._stop.is_set():
                    self.report(f"\n[MONITOR] stopped: {exc}")
                return
