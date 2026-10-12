"""
controller/handshake.py

One key-establishment EPOCH. Alice drives, Bob responds.

  1. Alice hands 4096 photons to the quantum channel (never to Bob).
  2. EPOCH_START / EPOCH_ACK: nonces, PQC capability, X25519 keys,
     Bob's ML-KEM key, Bob's measurement bases.
  3. If photons arrived:   sift -> sample QBER -> [QBER <= 11%?]
                           -> Cascade -> verify -> Toeplitz privacy amp.
  4. If both have PQC:     ML-KEM-768 encapsulation.
  5. Both compute the gear from what they observed (gear_controller).
  6. GEAR_COMMIT / GEAR_CONFIRM: each side signs the hash of the whole
     transcript (ML-DSA-65 if PQC, else Ed25519) with its pinned
     identity key. Any tampering -> signatures fail -> epoch aborted.
  7. HKDF(labelled secrets of that gear, nonces, gear, epoch, transcript)
     -> AES-256 session key + two key-confirmation keys. Each side proves
     it holds the same key (HMAC over the transcript) before using it.

Nothing derived in an epoch is used until step 6 succeeds.
"""

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Tuple

from controller import config
from controller.gear_controller import GearController, Observations, qber_acceptable
from crypto import classical, pqc
from crypto.aes import decrypt_message, encrypt_message
from crypto.bb84 import (calculate_qber, choose_sample, matching_indices, random_bases,
                         random_bits, remove_indices, select, sift_and_sample)
from crypto.error_correction import (answer_queries, block_sizes, initial_block_size,
                                     make_permutations, reconcile)
from crypto.identity import Identity, PeerKeys
from crypto.key_verification import tags_match, verification_tag
from crypto.privacy import (bits_to_bytes, new_toeplitz_seed, qber_upper_bound, secret_key_length,
                            toeplitz_hash, toeplitz_seed_bytes)
from network.messages import MessageType as M
from network.protocol import Session
from quantum import client as qclient
from quantum.channel import QuantumLinkError


class EpochAborted(Exception):
    pass


class AuthenticationError(Exception):
    pass


@dataclass
class NodeContext:
    role: str                       # "alice" or "bob"
    identity: Identity
    peer: PeerKeys
    gears: GearController
    channel_addr: Tuple[str, int] = (config.CHANNEL_HOST, config.CHANNEL_PORT)
    pqc_enabled: bool = True        # runtime switch to simulate a PQC failure
    peer_pqc_last: bool = True      # peer's PQC capability as of the last epoch
    qubits: int = config.RAW_QUBITS
    verbose: bool = True

    @property
    def peer_role(self) -> str:
        return "bob" if self.role == "alice" else "alice"

    @property
    def pqc_capable(self) -> bool:
        return (self.pqc_enabled and pqc.PQC_AVAILABLE
                and self.identity.mldsa_private is not None
                and self.peer.mldsa_public is not None)

    def log(self, tag: str, msg: str) -> None:
        if self.verbose:
            print(f"[{tag}] {msg}", flush=True)


@dataclass
class EpochKey:
    epoch: int
    gear: int
    key: bytes

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(b"fp|" + self.key).hexdigest()[:12]


# =====================================================================
# helpers shared by both roles
# =====================================================================

def _note_pqc(obs: Observations, ctx: NodeContext) -> None:
    status = {ctx.role: obs.pqc_local, ctx.peer_role: obs.pqc_peer}
    for who in ("alice", "bob"):
        if not status[who]:
            obs.reasons.append(f"Post-quantum crypto unavailable at {who.capitalize()}")


def _sig_message(role: str, epoch: int, gear: int, transcript: bytes) -> bytes:
    return f"HCQC-v1|{role}|epoch={epoch}|gear={gear}|".encode() + transcript


def _sign(ctx: NodeContext, use_pqc: bool, message: bytes) -> Tuple[str, bytes]:
    if use_pqc:
        return pqc.SIG_NAME, pqc.sig_sign(ctx.identity.mldsa_private, message)
    return "Ed25519", classical.ed25519_sign(ctx.identity.ed25519_private, message)


def _verify(ctx: NodeContext, use_pqc: bool, alg: str, message: bytes, sig: bytes) -> bool:
    expected = pqc.SIG_NAME if use_pqc else "Ed25519"
    if alg != expected:                       # no silent signature downgrade
        return False
    if use_pqc:
        return pqc.sig_verify(ctx.peer.mldsa_public, message, sig)
    return classical.ed25519_verify(ctx.peer.ed25519_public, message, sig)


KDF_LABEL = b"HCQC-v1"


def _encode_secret(label: bytes, value: bytes) -> bytes:
    """label | 4-byte length | value  - unambiguous, so no two different
    (qkd, kem) pairs can ever produce the same HKDF input."""
    return label + len(value).to_bytes(4, "big") + value


def derive_keys(gear: int, qkd_key: bytes, kem_ss: bytes, ecdh_ss: bytes,
                nonce_a: bytes, nonce_b: bytes, epoch: int, transcript: bytes):
    """
    Hybrid key schedule (HKDF-SHA256, RFC 5869).

      IKM  = only the secrets of the negotiated gear, each labelled + length-prefixed
               Gear 3: QKD key || ML-KEM secret   (secure if EITHER one is)
               Gear 2: ML-KEM secret
               Gear 1: X25519 secret
      salt = nonce_A || nonce_B                   (fresh per epoch)
      PRK  = HKDF-Extract(salt, IKM)
      each output key = HKDF-Expand(PRK, label | gear | epoch | transcript hash)

    Binding gear, epoch and the full transcript hash into every label means
    Alice and Bob get the same keys ONLY if they saw byte-identical handshakes
    and agreed on the same gear. Distinct labels give independent keys for
    encryption and for each side's key confirmation.
    """
    if len(nonce_a) != 16 or len(nonce_b) != 16:
        raise ValueError("nonces must be 16 bytes")
    if gear == 3:
        if not qkd_key or len(kem_ss) != 32:
            raise ValueError("Gear 3 needs both a QKD key and a 32-byte ML-KEM secret")
        ikm = _encode_secret(b"qkd", qkd_key) + _encode_secret(b"mlkem768", kem_ss)
    elif gear == 2:
        if len(kem_ss) != 32:
            raise ValueError("Gear 2 needs a 32-byte ML-KEM secret")
        ikm = _encode_secret(b"mlkem768", kem_ss)
    elif gear == 1:
        if len(ecdh_ss) != 32:
            raise ValueError("Gear 1 needs a 32-byte X25519 secret")
        ikm = _encode_secret(b"x25519", ecdh_ss)
    else:
        raise ValueError(f"unknown gear {gear}")

    def out(purpose: str) -> bytes:
        info = KDF_LABEL + f"|{purpose}|gear={gear}|epoch={epoch}|".encode() + transcript
        return classical.hkdf(ikm, salt=nonce_a + nonce_b, info=info)

    return {
        "session": out("session key"),
        "confirm_alice": out("key confirmation alice"),
        "confirm_bob": out("key confirmation bob"),
    }


def _confirm_tag(keys: dict, role: str, transcript: bytes) -> bytes:
    return classical.hmac_sha256(keys[f"confirm_{role}"], KDF_LABEL + f"|finished|{role}|".encode() + transcript)


# =====================================================================
# ALICE
# =====================================================================

def _alice_qkd(s: Session, ctx: NodeContext, obs: Observations,
               a_bits, a_bases, b_bases) -> bytes:
    match = matching_indices(a_bases, b_bases)
    sifted = select(a_bits, match)
    sample_idx = choose_sample(len(sifted), config.SAMPLE_FRACTION)
    a_sample = select(sifted, sample_idx)
    key = remove_indices(sifted, sample_idx)

    s.send(M.QKD_SIFT, {"bases": list(a_bases), "sample_idx": sample_idx, "sample_bits": a_sample})
    b_sample = s.recv(M.QKD_SAMPLE)["payload"]["bits"]
    obs.qber = calculate_qber(a_sample, b_sample)
    ctx.log("BB84", f"{len(a_bits)} photons -> {len(sifted)} sifted -> {len(sample_idx)} sacrificed "
                    f"-> QBER {obs.qber:.2%}")

    if not qber_acceptable(obs.qber):
        obs.reasons.append(f"QBER {obs.qber:.2%} > {config.QBER_THRESHOLD:.0%} threshold "
                           f"(noise or eavesdropper) - QKD key discarded")
        return b""

    # size Cascade blocks for the pessimistic QBER: a lucky sample must not
    # make the blocks too large to catch every error
    seed = secrets.randbits(64)
    k1 = initial_block_size(qber_upper_bound(obs.qber, len(sample_idx), 2.0))
    s.send(M.RECON_START, {"seed": seed, "k1": k1, "passes": config.CASCADE_PASSES})
    perms = make_permutations(len(key), seed, config.CASCADE_PASSES)

    def ask(queries):
        s.send(M.PARITY_REQUEST, {"q": [list(q) for q in queries]})
        return s.recv(M.PARITY_RESPONSE)["payload"]["p"]

    key, leaked, fixed = reconcile(key, perms, block_sizes(k1, config.CASCADE_PASSES, len(key)), ask)
    nonce = os.urandom(16)
    s.send(M.RECON_DONE, {"nonce": nonce.hex(), "tag": verification_tag(key, nonce, config.VERIFY_TAG_BITS)})
    if not s.recv(M.RECON_VERIFY)["payload"]["ok"]:
        obs.reasons.append("Keys still differ after Cascade - QKD key discarded")
        return b""
    ctx.log("CASCADE", f"{fixed} errors corrected, {leaked} parity bits revealed")

    length, e_up = secret_key_length(len(key), obs.qber, len(sample_idx), leaked,
                                     config.VERIFY_TAG_BITS, config.PA_EPSILON, config.PE_SIGMAS)
    if length < config.MIN_QKD_KEY_BITS:
        obs.reasons.append(f"Only {length} secret bits survive privacy amplification "
                           f"(need {config.MIN_QKD_KEY_BITS}) - QKD key discarded")
        return b""

    pa_seed = new_toeplitz_seed(len(key), length)          # n + l - 1 truly random bits
    s.send(M.PRIVACY_SEED, {"seed": pa_seed.hex()})
    final = toeplitz_hash(key, length, pa_seed)
    obs.qkd_key_bits = length
    ctx.log("PRIVACY", f"{len(key)} bits -> {length} secret bits (QBER bound {e_up:.2%})")
    return bits_to_bytes(final)


def alice_run_epoch(s: Session, ctx: NodeContext, epoch: int) -> EpochKey:
    obs = Observations(pqc_local=ctx.pqc_capable)
    nonce_a = os.urandom(16)
    x_sk, x_pub = classical.x25519_keypair()

    # 1. photons -> quantum channel
    sid = secrets.token_hex(8)
    a_bits, a_bases = random_bits(ctx.qubits), random_bases(ctx.qubits)
    link_reason = None
    try:
        qclient.send_photons(ctx.channel_addr, sid, a_bits, a_bases)
        obs.qkd_attempted = True
    except QuantumLinkError as exc:
        link_reason = str(exc)
        obs.reasons.append(f"Quantum channel failure: {exc}")

    # 2. hello
    s.begin_transcript()
    s.send(M.EPOCH_START, {
        "epoch": epoch, "nonce": nonce_a.hex(), "pqc": obs.pqc_local, "x25519": x_pub.hex(),
        "qkd": {"attempt": obs.qkd_attempted, "sid": sid, "n": ctx.qubits, "reason": link_reason},
    })
    ack = s.recv(M.EPOCH_ACK)["payload"]
    nonce_b, bob_x = bytes.fromhex(ack["nonce"]), bytes.fromhex(ack["x25519"])
    obs.pqc_peer = bool(ack["pqc"])
    ctx.peer_pqc_last = obs.pqc_peer
    _note_pqc(obs, ctx)

    # 3. QKD
    qkd_key = b""
    if obs.qkd_attempted:
        if ack["qkd"]["bases"] is None:
            obs.qkd_attempted = False
            obs.reasons.append(f"Quantum channel failure: {ack['qkd']['reason']}")
        else:
            qkd_key = _alice_qkd(s, ctx, obs, a_bits, a_bases, ack["qkd"]["bases"])

    # 4. PQC
    kem_ss = b""
    if obs.pqc_ok:
        kem_ss, ct = pqc.kem_encapsulate(bytes.fromhex(ack["kem_pk"]))
        s.send(M.KEM_CIPHERTEXT, {"ct": ct.hex()})
    ecdh_ss = classical.x25519_shared(x_sk, bob_x)

    # 5. gear
    gear = ctx.gears.decide(obs)
    if not ctx.gears.permitted(gear):
        reason = f"negotiated Gear {gear} is below the minimum Gear {ctx.gears.min_gear}"
        s.send(M.EPOCH_ABORT, {"reason": reason})
        s.end_transcript()
        raise EpochAborted(reason)

    # 6. derive keys, then signed commit + key confirmation
    transcript = s.transcript_hash()
    keys = derive_keys(gear, qkd_key, kem_ss, ecdh_ss, nonce_a, nonce_b, epoch, transcript)
    alg, sig = _sign(ctx, obs.pqc_ok, _sig_message("alice", epoch, gear, transcript))
    s.send(M.GEAR_COMMIT, {"gear": gear, "alg": alg, "sig": sig.hex(),
                           "mac": _confirm_tag(keys, "alice", transcript).hex()})
    conf = s.recv(M.GEAR_CONFIRM)["payload"]
    if not _verify(ctx, obs.pqc_ok, conf["alg"], _sig_message("bob", epoch, gear, transcript),
                   bytes.fromhex(conf["sig"])):
        raise AuthenticationError("Bob's transcript signature is invalid - possible man-in-the-middle")
    if not classical.hmac_verify(keys["confirm_bob"], KDF_LABEL + b"|finished|bob|" + transcript,
                                 bytes.fromhex(conf["mac"])):
        raise AuthenticationError("Bob derived a different key - key confirmation failed")
    s.end_transcript()
    ctx.log("AUTH", f"transcript signed and verified ({alg}); key confirmed by both sides")

    # 7. key
    ctx.gears.commit(epoch, gear, obs)
    return EpochKey(epoch, gear, keys["session"])


# =====================================================================
# BOB
# =====================================================================

def _bob_qkd(s: Session, ctx: NodeContext, obs: Observations, b_bits, b_bases) -> bytes:
    sift = s.recv(M.QKD_SIFT)["payload"]
    if len(sift["bases"]) != len(b_bases):
        raise EpochAborted("basis list length mismatch")
    sample_idx = sift["sample_idx"]
    b_sample, key = sift_and_sample(b_bits, sift["bases"], b_bases, sample_idx)
    s.send(M.QKD_SAMPLE, {"bits": b_sample})
    obs.qber = calculate_qber(sift["sample_bits"], b_sample)
    ctx.log("BB84", f"sampled {len(sample_idx)} sifted bits -> QBER {obs.qber:.2%}")

    if not qber_acceptable(obs.qber):
        obs.reasons.append(f"QBER {obs.qber:.2%} > {config.QBER_THRESHOLD:.0%} threshold "
                           f"(noise or eavesdropper) - QKD key discarded")
        return b""

    r = s.recv(M.RECON_START)["payload"]
    passes = min(int(r["passes"]), 16)
    perms = make_permutations(len(key), r["seed"], passes)
    leaked = 0
    while True:
        pkt = s.recv(M.PARITY_REQUEST, M.RECON_DONE)
        if pkt["type"] == M.RECON_DONE.value:
            break
        queries = pkt["payload"]["q"]
        leaked += len(queries)
        s.send(M.PARITY_RESPONSE, {"p": answer_queries(key, perms, queries)})

    done = pkt["payload"]
    ok = tags_match(verification_tag(key, bytes.fromhex(done["nonce"]), config.VERIFY_TAG_BITS), done["tag"])
    s.send(M.RECON_VERIFY, {"ok": ok})
    if not ok:
        obs.reasons.append("Keys still differ after Cascade - QKD key discarded")
        return b""
    ctx.log("CASCADE", f"{leaked} parity bits revealed")

    length, _ = secret_key_length(len(key), obs.qber, len(sample_idx), leaked,
                                  config.VERIFY_TAG_BITS, config.PA_EPSILON, config.PE_SIGMAS)
    if length < config.MIN_QKD_KEY_BITS:
        obs.reasons.append(f"Only {length} secret bits survive privacy amplification "
                           f"(need {config.MIN_QKD_KEY_BITS}) - QKD key discarded")
        return b""

    pa_seed = bytes.fromhex(s.recv(M.PRIVACY_SEED)["payload"]["seed"])
    if len(pa_seed) != toeplitz_seed_bytes(len(key), length):
        raise EpochAborted("privacy-amplification seed has the wrong size")
    final = toeplitz_hash(key, length, pa_seed)
    obs.qkd_key_bits = length
    ctx.log("PRIVACY", f"{len(key)} bits -> {length} secret bits")
    return bits_to_bytes(final)


def bob_handle_epoch(s: Session, ctx: NodeContext, start_packet: dict) -> EpochKey:
    s.begin_transcript(include_last_received=True)
    p = start_packet["payload"]
    epoch = int(p["epoch"])
    nonce_a, alice_x = bytes.fromhex(p["nonce"]), bytes.fromhex(p["x25519"])
    obs = Observations(pqc_local=ctx.pqc_capable, pqc_peer=bool(p["pqc"]))

    nonce_b = os.urandom(16)
    x_sk, x_pub = classical.x25519_keypair()
    kem_sk, kem_pk = (pqc.kem_keypair() if obs.pqc_ok else (None, None))

    # measure photons
    q = p["qkd"]
    reply = {"bases": None, "reason": None}
    b_bits = b_bases = None
    if q["attempt"]:
        b_bases = random_bases(int(q["n"]))
        try:
            b_bits = qclient.measure_photons(ctx.channel_addr, q["sid"], b_bases)
            reply["bases"] = b_bases
            obs.qkd_attempted = True
        except QuantumLinkError as exc:
            reply["reason"] = str(exc)
            obs.reasons.append(f"Quantum channel failure: {exc}")
    else:
        obs.reasons.append(f"Quantum channel failure: {q.get('reason')}")
    _note_pqc(obs, ctx)

    s.send(M.EPOCH_ACK, {"nonce": nonce_b.hex(), "pqc": obs.pqc_local, "x25519": x_pub.hex(),
                         "kem_pk": kem_pk.hex() if kem_pk else None, "qkd": reply})

    qkd_key = _bob_qkd(s, ctx, obs, b_bits, b_bases) if b_bits is not None else b""

    kem_ss = b""
    if obs.pqc_ok:
        kem_ss = pqc.kem_decapsulate(kem_sk, bytes.fromhex(s.recv(M.KEM_CIPHERTEXT)["payload"]["ct"]))
    ecdh_ss = classical.x25519_shared(x_sk, alice_x)

    gear = ctx.gears.decide(obs)
    commit = s.recv(M.GEAR_COMMIT)["payload"]          # raises if Alice aborted
    transcript = s.hash_before_last_recv

    def abort(reason, exc=EpochAborted):
        s.send(M.EPOCH_ABORT, {"reason": reason})
        s.end_transcript()
        raise exc(reason)

    if int(commit["gear"]) != gear:
        abort(f"gear mismatch: Alice proposed {commit['gear']}, Bob computed {gear} (possible downgrade)")
    if not _verify(ctx, obs.pqc_ok, commit["alg"], _sig_message("alice", epoch, gear, transcript),
                   bytes.fromhex(commit["sig"])):
        abort("Alice's transcript signature is invalid - possible man-in-the-middle", AuthenticationError)
    if not ctx.gears.permitted(gear):
        abort(f"negotiated Gear {gear} is below Bob's minimum Gear {ctx.gears.min_gear}")

    keys = derive_keys(gear, qkd_key, kem_ss, ecdh_ss, nonce_a, nonce_b, epoch, transcript)
    if not classical.hmac_verify(keys["confirm_alice"], KDF_LABEL + b"|finished|alice|" + transcript,
                                 bytes.fromhex(commit.get("mac", ""))):
        abort("Alice derived a different key - key confirmation failed", AuthenticationError)

    alg, sig = _sign(ctx, obs.pqc_ok, _sig_message("bob", epoch, gear, transcript))
    s.send(M.GEAR_CONFIRM, {"alg": alg, "sig": sig.hex(),
                            "mac": _confirm_tag(keys, "bob", transcript).hex()})
    s.end_transcript()
    ctx.log("AUTH", f"transcript signed and verified ({alg}); key confirmed by both sides")

    ctx.gears.commit(epoch, gear, obs)
    return EpochKey(epoch, gear, keys["session"])


# =====================================================================
# QBER probe - the continuous health check between epochs
# =====================================================================
#
# A probe is a small batch of photons whose bits are ALL revealed and
# thrown away. It never produces key material; it only measures the
# channel so the monitor can decide whether to re-key. Every gear
# decision is still made inside a full, signed epoch.

@dataclass
class ProbeResult:
    qber: float = None           # None if no photons got through
    sifted: int = 0
    error: str = None

    @property
    def link_ok(self) -> bool:
        return self.error is None and self.qber is not None


def alice_probe(s: Session, ctx: NodeContext, n: int) -> ProbeResult:
    sid = secrets.token_hex(8)
    bits, bases = random_bits(n), random_bases(n)
    try:
        qclient.send_photons(ctx.channel_addr, sid, bits, bases)
    except QuantumLinkError as exc:
        return ProbeResult(error=str(exc))
    s.send(M.QBER_PROBE, {"sid": sid, "n": n})
    reply = s.recv(M.PROBE_REPLY)["payload"]
    if reply.get("error"):
        return ProbeResult(error=reply["error"])
    match = matching_indices(bases, reply["bases"])
    return ProbeResult(qber=calculate_qber(select(bits, match), select(reply["bits"], match)),
                       sifted=len(match))


def bob_handle_probe(s: Session, ctx: NodeContext, packet: dict) -> None:
    p = packet["payload"]
    bases = random_bases(min(int(p["n"]), 65536))
    try:
        bits = qclient.measure_photons(ctx.channel_addr, p["sid"], bases)
        s.send(M.PROBE_REPLY, {"bases": bases, "bits": bits})
    except QuantumLinkError as exc:
        s.send(M.PROBE_REPLY, {"error": str(exc)})


# =====================================================================
# messages under the current epoch key
# =====================================================================

def _aad(epoch: int, seq: int, gear: int) -> bytes:
    return f"HCQC-v1|epoch={epoch}|seq={seq}|gear={gear}".encode()


def seal(k: EpochKey, seq: int, text: str) -> dict:
    nonce, ct = encrypt_message(k.key, text, _aad(k.epoch, seq, k.gear))
    return {"epoch": k.epoch, "seq": seq, "nonce": nonce.hex(), "ct": ct.hex()}


def open_sealed(k: EpochKey, payload: dict) -> str:
    if int(payload["epoch"]) != k.epoch:
        raise ValueError(f"message for epoch {payload['epoch']}, current epoch is {k.epoch}")
    return decrypt_message(k.key, bytes.fromhex(payload["nonce"]), bytes.fromhex(payload["ct"]),
                           _aad(k.epoch, int(payload["seq"]), k.gear))
