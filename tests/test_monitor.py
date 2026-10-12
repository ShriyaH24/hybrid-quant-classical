"""
The monitor must shift gears by itself: no /rekey, only changes in the
channel (Eve, link, noise) or in PQC availability.
"""

import threading

from controller.handshake import bob_handle_epoch, bob_handle_probe, alice_run_epoch
from controller.monitor import ChannelMonitor, predict_gear
from controller.handshake import ProbeResult
from network.messages import MessageType as M


def start_bob(lab):
    """Bob's real event loop (epochs + probes) in a thread."""
    def loop():
        while True:
            try:
                pkt = lab.sb.recv()
            except Exception:
                return
            if pkt["type"] == M.EPOCH_START.value:
                try:
                    bob_handle_epoch(lab.sb, lab.bob, pkt)
                except Exception:
                    pass
            elif pkt["type"] == M.QBER_PROBE.value:
                bob_handle_probe(lab.sb, lab.bob, pkt)
            elif pkt["type"] == M.CLOSE.value:
                return
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t


def make_monitor(lab):
    state = {"key": None, "epoch": 0}
    lock = threading.RLock()

    def rekey(why):
        state["epoch"] += 1
        state["key"] = alice_run_epoch(lab.sa, lab.alice, state["epoch"])

    rekey("start")
    mon = ChannelMonitor(lab.sa, lab.alice, lock, lambda: state["key"].gear, rekey,
                         interval=999, report=lambda m: None)
    return mon, state


def test_prediction_table():
    assert predict_gear(ProbeResult(qber=0.02, sifted=500), True, True)[0] == 3
    assert predict_gear(ProbeResult(qber=0.25, sifted=500), True, True)[0] == 2
    assert predict_gear(ProbeResult(qber=0.07, sifted=500), True, True)[0] == 2   # < 11% but no key
    assert predict_gear(ProbeResult(error="link down"), True, True)[0] == 2
    assert predict_gear(ProbeResult(error="link down"), False, True)[0] == 1


def test_monitor_shifts_gears_without_manual_rekey(lab):
    start_bob(lab)
    mon, state = make_monitor(lab)
    assert state["key"].gear == 3

    d = mon.check_once()                       # healthy: nothing happens
    assert d.trigger is None and state["key"].gear == 3

    lab.channel.eve = True                     # Eve appears
    d = mon.check_once()
    assert d.trigger == "DOWNSHIFT" and state["key"].gear == 2

    lab.channel.eve = False                    # Eve leaves: needs 2 healthy probes
    assert mon.check_once().trigger is None and state["key"].gear == 2
    d = mon.check_once()
    assert d.trigger == "UPSHIFT" and state["key"].gear == 3

    lab.channel.link_up = False                # fibre cut
    lab.alice.pqc_enabled = False              # and PQC fails
    d = mon.check_once()
    assert d.trigger == "DOWNSHIFT" and state["key"].gear == 1

    lab.channel.link_up = True
    lab.alice.pqc_enabled = True
    mon.check_once()
    mon.check_once()
    assert state["key"].gear == 3
    assert [h.gear for h in lab.bob.gears.history] == [3, 2, 3, 1, 3]
