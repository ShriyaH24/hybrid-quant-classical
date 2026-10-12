"""
controller/config.py

All tunable numbers in one place.
"""

# ---- Gear 3 trigger -------------------------------------------------
QBER_THRESHOLD = 0.11        # BB84 bound (Shor-Preskill): above this, no secret key is possible

# ---- BB84 -----------------------------------------------------------
RAW_QUBITS = 4096            # photons per epoch (~2048 survive sifting)
SAMPLE_FRACTION = 0.25       # share of sifted bits sacrificed to estimate QBER
MIN_QKD_KEY_BITS = 256       # below this the QKD key is not worth using -> treat QKD as failed
PE_SIGMAS = 3.0              # statistical margin added to the QBER estimate
PA_EPSILON = 1e-9            # privacy-amplification security parameter
VERIFY_TAG_BITS = 64         # bits revealed by the post-Cascade key check
CASCADE_PASSES = 6

# ---- Continuous monitoring -----------------------------------------
PROBE_QUBITS = 1024          # photons per health probe (all revealed, never used as key)
PROBE_INTERVAL = 5.0         # seconds between probes
UPSHIFT_CONFIRMATIONS = 2    # healthy probes in a row before shifting UP (avoids flapping)
EC_EFFICIENCY = 1.2          # Cascade leaks ~1.2x the Shannon limit (used to predict key yield)

# ---- Session --------------------------------------------------------
REKEY_EVERY = 3              # Alice starts a new epoch after this many messages
BOB_HOST, BOB_PORT = "127.0.0.1", 5000
CHANNEL_HOST, CHANNEL_PORT = "127.0.0.1", 6000

# ---- Policy ---------------------------------------------------------
MIN_GEAR = 1                 # set to 2 to refuse quantum-vulnerable Gear 1 entirely
