"""
tools/validate_cascade.py

Statistical validation of the Cascade reconciliation, run exactly the way
an epoch runs it: a sampled QBER estimate (25 % of ~2048 sifted bits),
blocks sized from the pessimistic estimate, 6 shuffled passes, then the
64-bit verification tag.

    python tools/validate_cascade.py               # 500 runs per QBER
    python tools/validate_cascade.py --trials 2000

Columns
  fail      runs where Alice's key still differed from Bob's after Cascade
  caught    of those, how many the verification tag rejected (must be all)
  f         leak efficiency = parities revealed / (n * h(QBER)); 1.0 is the
            Shannon limit, Cascade typically runs at 1.1 - 1.3
  rounds    network round trips per reconciliation
  key bits  secret bits left after privacy amplification (n = 1536)

Exit code 1 if any QBER up to 5 % fails more than 0.5 % of runs, any
failure slips past verification, or Bob's key is ever modified.
"""

import argparse
import os
import secrets
import statistics
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from controller import config                                                  # noqa: E402
from crypto.error_correction import (answer_queries, block_sizes,             # noqa: E402
                                     initial_block_size, make_permutations, reconcile)
from crypto.key_verification import tags_match, verification_tag              # noqa: E402
from crypto.privacy import binary_entropy, qber_upper_bound, secret_key_length  # noqa: E402

N_SIFTED = 2048
N_SAMPLE = int(N_SIFTED * config.SAMPLE_FRACTION)
N_KEY = N_SIFTED - N_SAMPLE
RNG = secrets.SystemRandom()


def one_run(q: float):
    bob_all = [secrets.randbits(1) for _ in range(N_SIFTED)]
    alice_all = [b ^ (RNG.random() < q) for b in bob_all]
    sample = set(RNG.sample(range(N_SIFTED), N_SAMPLE))
    q_est = sum(alice_all[i] != bob_all[i] for i in sample) / N_SAMPLE
    alice = [b for i, b in enumerate(alice_all) if i not in sample]
    bob = tuple(b for i, b in enumerate(bob_all) if i not in sample)     # tuple: must stay untouched
    true_errors = sum(a != b for a, b in zip(alice, bob))

    passes = config.CASCADE_PASSES
    perms = make_permutations(N_KEY, secrets.randbits(64), passes)
    k1 = initial_block_size(qber_upper_bound(q_est, N_SAMPLE, 2.0))
    rounds = [0]

    def ask(queries):
        rounds[0] += 1
        return answer_queries(bob, perms, queries)

    key, leaked, fixed = reconcile(alice, perms, block_sizes(k1, passes, N_KEY), ask)
    nonce = secrets.token_bytes(16)
    verified = tags_match(verification_tag(key, nonce), verification_tag(list(bob), nonce))
    bits, _ = secret_key_length(N_KEY, q_est, N_SAMPLE, leaked, config.VERIFY_TAG_BITS,
                                config.PA_EPSILON, config.PE_SIGMAS)
    return {
        "failed": key != list(bob), "verified": verified, "true_errors": true_errors,
        "fixed": fixed, "leaked": leaked, "rounds": rounds[0], "bits": bits,
    }


def main():
    ap = argparse.ArgumentParser(description="Validate Cascade reconciliation")
    ap.add_argument("--trials", type=int, default=500)
    ap.add_argument("--qbers", default="0.005,0.01,0.02,0.03,0.04,0.05,0.06,0.08,0.10")
    a = ap.parse_args()

    print(f"Cascade validation: {a.trials} runs per QBER, key {N_KEY} bits after sampling, "
          f"{config.CASCADE_PASSES} passes\n")
    print(f"{'QBER':>6} {'fail':>8} {'caught':>7} {'fixed=errors':>13} {'f':>6} {'rounds':>7} {'key bits':>9}")
    ok = True
    for q in [float(x) for x in a.qbers.split(",")]:
        runs = [one_run(q) for _ in range(a.trials)]
        fails = [r for r in runs if r["failed"]]
        caught = sum(not r["verified"] for r in fails)
        exact = sum(r["fixed"] == r["true_errors"] for r in runs if not r["failed"])
        f = statistics.mean(r["leaked"] / max(1e-9, N_KEY * binary_entropy(q)) for r in runs)
        rounds = statistics.mean(r["rounds"] for r in runs)
        bits = statistics.mean(r["bits"] for r in runs)
        rate = len(fails) / a.trials
        print(f"{q:6.1%} {rate:8.2%} {caught:>3}/{len(fails):<3} {exact:>6}/{a.trials - len(fails):<6}"
              f" {f:6.2f} {rounds:7.1f} {bits:9.0f}")
        if caught != len(fails):
            ok = False
            print("   !! a failed reconciliation passed verification")
        if q <= 0.05 and rate > 0.005:
            ok = False
            print("   !! failure rate above 0.5 %")
        if any(r["verified"] and r["failed"] for r in runs):
            ok = False

    print("\nRESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
