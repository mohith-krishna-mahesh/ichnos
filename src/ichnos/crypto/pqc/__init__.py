"""Post-Quantum Cryptography (PQC) analysis and educational implementations.

CAVEAT:
Educational and CTF-analysis scope only. Not intended for production cryptographic use.
These implementations demonstrate the underlying mathematical mechanics (Lattices,
Module-LWE, SIS, Polynomial Rings) for security analysis and vulnerability assessment.
"""

from ichnos.crypto.pqc.attacks import audit_pqc_parameters, estimate_lwe_hardness
from ichnos.crypto.pqc.dilithium import EducationalDilithium
from ichnos.crypto.pqc.kyber import EducationalKyber
from ichnos.crypto.pqc.lattice import (
    babai_nearest_plane,
    babai_round_off,
    gram_schmidt,
    lattice_determinant,
)
from ichnos.crypto.pqc.ntru import NTRUEncrypt

__all__ = [
    "EducationalDilithium",
    "EducationalKyber",
    "NTRUEncrypt",
    "audit_pqc_parameters",
    "babai_nearest_plane",
    "babai_round_off",
    "estimate_lwe_hardness",
    "gram_schmidt",
    "lattice_determinant",
]
