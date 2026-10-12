# Hybrid Classical–Quantum Crypt

An adaptive key-establishment system that monitors the quantum channel's
error rate (QBER) and shifts between three security "gears":

| Gear | Suite | When | Security |
|------|-------|------|----------|
| **3** | QKD (BB84) + ML-KEM-768 + AES-256-GCM | QBER ≤ 11 % and both nodes have PQC | Hybrid: secret unless BOTH QKD and ML-KEM are broken |
| **2** | ML-KEM-768 + ML-DSA-65 + AES-256-GCM | QKD unusable (QBER > 11 %, link down, too little key) | Post-quantum |
| **1** | X25519 ECDH + AES-256-GCM (Ed25519 auth) | No QKD **and** no PQC | Classical only – documented quantum risk |

The gear is re-negotiated at every **epoch** (re-key), so the link
steps down when the channel degrades and steps back up when it recovers.

> This is an educational **simulation**: the quantum channel is
> simulated with Qiskit Aer. The cryptography (ML-KEM, ML-DSA, X25519,
> Ed25519, AES-GCM, HKDF) is real.

---

## Setup

```bash
python -m venv venv
venv\Scripts\activate            # Windows   (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
python -m crypto.identity        # once: creates keys/ with Alice's and Bob's identity keys
```

## Run (three terminals, from the project root)

```bash
python quantum/channel_server.py     # 1. the quantum channel + attack console
python bob/bob.py                    # 2. Bob listens
python alice/alice.py                # 3. Alice connects and negotiates epoch 1
```

### Continuous monitoring (automatic gear shifts)

Alice runs a background **monitor**: every 5 s it sends 1024 probe photons
(all revealed and discarded - never key material), measures the QBER and
predicts which gear the channel can support right now.

```
Monitor QBER  ->  compare with 11 % bound / key-yield bound  ->  trigger re-key
  predicted gear < current   ->  re-key immediately         (DOWNSHIFT)
  predicted gear > current   ->  re-key after 2 healthy probes (UPSHIFT, no flapping)
```

The probe only *triggers*; the gear itself is still decided inside the full,
signed epoch from that epoch's own QBER sample.

### Demo script - you only play "the environment"

| Where | Type | What happens on its own |
|-------|------|-------------------------|
| alice | `hello` | sent in **Gear 3** |
| channel | `eve on` | next probe sees ~25 % QBER -> **DOWNSHIFT 3 -> 2** |
| channel | `eve off` | 2 healthy probes -> **UPSHIFT 2 -> 3** |
| channel | `noise 0.07` | QBER < 11 % but too little secret key -> **3 -> 2** |
| channel | `noise 0.02` | **2 -> 3** |
| channel + alice | `link down` and `/pqc off` | **3 -> 1** (+ quantum-risk warning) |
| channel + alice | `link up` and `/pqc on` | **1 -> 3** |
| alice | `/status` | gear history with the trigger for every shift |

In the channel console, `watch on` shows a line per probe (hidden by default so
they don't break up your typing); `noise 5` and `noise 5%` both mean 5 %.
In Alice, `/quiet` hides the per-probe lines, `--probe-every 3` probes faster,
`--probe-every 0` turns the monitor off (manual `/rekey` only).
Other knobs: `python bob/bob.py --no-pqc`, and `--min-gear 2` on either
node to refuse Gear 1 entirely. Alice also rotates keys every 3 messages
(`--rekey-every N`).

---

## How one epoch works

```
Alice ──photons(bits, bases)──▶ Quantum channel ◀──measure(bases)── Bob
          (Eve / noise / link state live here; Bob never sees Alice's bits)

Alice ◀──────────────── classical TCP (signed at the end) ──────────────▶ Bob
  EPOCH_START / EPOCH_ACK   nonces, PQC capability, X25519 keys, ML-KEM key, Bob's bases
  QKD_SIFT / QKD_SAMPLE     sift, reveal a random 25 % sample, estimate QBER
  ── QBER > 11 %? → QKD key discarded (trigger) ──
  Cascade (6 shuffled passes, batched)   every revealed parity is counted
  RECON_DONE / VERIFY       64-bit check that both keys match
  PRIVACY_SEED              Toeplitz hashing shrinks the key by everything leaked
  KEM_CIPHERTEXT            ML-KEM-768 encapsulation (if both have PQC)
  GEAR_COMMIT / CONFIRM     both compute the gear independently; each signs the
                            SHA-256 of the whole transcript with its pinned key
                            (ML-DSA-65, or Ed25519 in Gear 1)
  → HKDF(QKD key ‖ ML-KEM secret  |  ML-KEM secret  |  ECDH secret) = AES-256 key
```

### Key schedule (how the gear's secrets become the AES key)

```
IKM  = "qkd"|len|QKD key  ||  "mlkem768"|len|ML-KEM secret      (Gear 3)
       "mlkem768"|len|ML-KEM secret                              (Gear 2)
       "x25519"|len|X25519 secret                                (Gear 1)
salt = nonce_A || nonce_B
key_X = HKDF-SHA256(salt, IKM, info = "HCQC-v1|X|gear|epoch|" + transcript hash)
        X = session key, key confirmation alice, key confirmation bob
```

* Each secret is labelled and length-prefixed, so they can't be shifted into
  one another; only the secrets of the negotiated gear are used.
* Gear, epoch and the hash of every handshake byte are in every label, so the
  two sides get equal keys **only** after byte-identical handshakes.
* Each side sends an HMAC over the transcript under its confirmation key
  (with its signature); a different key means the epoch is aborted.
* Privacy amplification uses a Toeplitz matrix with **n + l − 1 fresh random
  bits** from the OS (not a short seed stretched by a PRNG), as the leftover
  hash lemma requires; the seed is public and covered by the signatures.
  Final QKD keys are whole bytes, so no padding enters the KDF.

### Why each piece is there

* **Separate channel process** – Alice's raw bits only go to the
  channel, never over the Alice–Bob link.
* **Sampled QBER** – the bits used to estimate the error rate are
  published and then thrown away; they never become key.
* **Cascade with shuffling + backtracking** – a single unshuffled pass
  misses every block with two errors; real Cascade re-checks earlier
  passes whenever a bit is fixed.
* **Privacy amplification sized by the leak** –
  `secret bits = n·(1 − h(QBER_upper)) − parities leaked − 64 − 2·log2(1/ε)`.
  At ~2 % QBER, 4096 photons yield ~650–800 secret bits; above ~5–6 %
  the result drops below 256 bits and the system shifts to Gear 2 even
  though QBER is under 11 %.
* **Signed transcript** – BB84 needs an authenticated classical
  channel. Signing the hash of every handshake byte also stops
  downgrade attacks: stripping `"pqc": true` in transit changes the
  transcript and the signatures fail.
* **Both sides compute the gear** – a mismatch aborts the epoch.
* **AES-GCM associated data** binds each message to its epoch,
  sequence number and gear (no replay into another epoch).

## Project layout

```
alice/alice.py              interactive sender, drives epochs
bob/bob.py                  responder, decrypts messages
controller/config.py        thresholds and tunables
controller/gear_controller.py  3-gear decision + transition log
controller/monitor.py       continuous QBER probing -> automatic gear triggers
controller/handshake.py     one epoch: BB84 post-processing, PQC, signatures, HKDF
crypto/bb84.py              random bits/bases (secrets), sifting, sampling
crypto/error_correction.py  Cascade
crypto/privacy.py           Toeplitz hashing + secret-key-length bound
crypto/key_verification.py  post-Cascade check
crypto/pqc.py               ML-KEM-768, ML-DSA-65
crypto/classical.py         X25519, Ed25519, HKDF
crypto/aes.py               AES-256-GCM
crypto/identity.py          identity key generation / loading
network/                    framing, transcript-hashing session, message types
quantum/                    encoder, decoder, channel (noise/Eve), channel server
tests/                      unit tests + end-to-end gear transitions
```

## Tests

```bash
pytest -q
```

Covers the gear table, Cascade, privacy amplification, channel physics
(noise ≈ setting, Eve ≈ 25 % QBER) and full epochs for every
transition: 3, Eve → 2, link down → 2, no PQC → 1, min-gear abort,
forged identity rejected, 3 → 2 → 1 → 3 recovery, and the monitor
shifting 3 → 2 → 3 → 1 → 3 with no manual re-key.

## Limitations (honest list)

* The quantum channel is simulated; there is no real photon source.
* The finite-key correction is a normal approximation, not a rigorous
  finite-key proof.
* After HKDF the session is protected by AES-256-GCM, so message secrecy
  is computational (quantum-resistant), not information-theoretic.
* Both identity keys are generated on one machine for the demo; in
  practice each party keeps its own private key.
* Only Alice sends messages; Bob responds to handshakes.
