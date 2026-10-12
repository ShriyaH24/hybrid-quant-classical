"""
network/messages.py

Every message type actually used by the protocol.
"""

from enum import Enum


class MessageType(Enum):
    # ---- Alice <-> Bob: epoch handshake ----------------------
    EPOCH_START = "EPOCH_START"          # nonce, capabilities, X25519 key, QKD attempt
    EPOCH_ACK = "EPOCH_ACK"              # nonce, capabilities, X25519 key, ML-KEM key, Bob's bases
    EPOCH_ABORT = "EPOCH_ABORT"          # policy refused the negotiated gear

    # ---- BB84 post-processing --------------------------------
    QKD_SIFT = "QKD_SIFT"                # Alice's bases + QBER sample (positions and her bits)
    QKD_SAMPLE = "QKD_SAMPLE"            # Bob's bits at the sample positions
    RECON_START = "RECON_START"          # Cascade permutation seed + block size
    PARITY_REQUEST = "PARITY_REQUEST"    # batched parity queries
    PARITY_RESPONSE = "PARITY_RESPONSE"
    RECON_DONE = "RECON_DONE"            # verification nonce + tag
    RECON_VERIFY = "RECON_VERIFY"        # tags matched?
    PRIVACY_SEED = "PRIVACY_SEED"        # Toeplitz seed

    # ---- Post-quantum ----------------------------------------
    KEM_CIPHERTEXT = "KEM_CIPHERTEXT"    # ML-KEM-768 encapsulation

    # ---- Gear negotiation (signed transcript) ----------------
    GEAR_COMMIT = "GEAR_COMMIT"          # Alice's gear + signature
    GEAR_CONFIRM = "GEAR_CONFIRM"        # Bob's signature

    # ---- Continuous QBER monitoring (between epochs) ---------
    QBER_PROBE = "QBER_PROBE"            # Alice sent probe photons; Bob please measure
    PROBE_REPLY = "PROBE_REPLY"          # Bob's bases + results (all sacrificed) or error

    # ---- Secure messaging ------------------------------------
    ENCRYPTED_MESSAGE = "ENCRYPTED_MESSAGE"
    CLOSE = "CLOSE"
    ERROR = "ERROR"

    # ---- Node <-> quantum channel server ---------------------
    Q_SEND = "Q_SEND"                    # Alice hands photons (bits+bases) to the channel
    Q_SEND_ACK = "Q_SEND_ACK"
    Q_MEASURE = "Q_MEASURE"              # Bob measures in his bases
    Q_RESULT = "Q_RESULT"
    Q_ERROR = "Q_ERROR"                  # link down / unknown session
