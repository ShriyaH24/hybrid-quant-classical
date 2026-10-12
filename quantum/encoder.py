"""
quantum/encoder.py

Alice's photon source: encodes one bit in one basis as a 1-qubit circuit.

  bit 0, basis Z (+) -> |0>
  bit 1, basis Z (+) -> |1>      (X)
  bit 0, basis X (x) -> |+>      (H)
  bit 1, basis X (x) -> |->      (X then H)
"""

from qiskit import QuantumCircuit


def is_diagonal(basis) -> bool:
    return basis in (1, "x", "X")


def prepare_qubit(bit: int, basis) -> QuantumCircuit:
    qc = QuantumCircuit(1, 1)
    if bit == 1:
        qc.x(0)
    if is_diagonal(basis):
        qc.h(0)
    return qc
