"""
quantum/decoder.py

Measurement in a chosen basis, run in ONE batched Aer job
(building a simulator per qubit is ~100x slower).
"""

from typing import List, Sequence

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

from quantum.encoder import is_diagonal

_SIMULATOR = AerSimulator()


def add_measurement(qc: QuantumCircuit, basis) -> QuantumCircuit:
    """Rotate X-basis back to Z with H, then measure. Returns a new circuit."""
    m = qc.copy()
    if is_diagonal(basis):
        m.h(0)
    m.measure(0, 0)
    return m


def measure_all(circuits: Sequence[QuantumCircuit], bases: Sequence) -> List[int]:
    """Measure circuit i in bases[i]; one shot each."""
    if not circuits:
        return []
    jobs = [add_measurement(qc, b) for qc, b in zip(circuits, bases)]
    result = _SIMULATOR.run(jobs, shots=1, memory=True).result()
    return [int(result.get_memory(i)[0]) for i in range(len(jobs))]
