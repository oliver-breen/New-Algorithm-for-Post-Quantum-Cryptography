"""
HQC (Hamming Quasi-Cyclic) primitives and KEM scaffolding.

Phase 3 work-in-progress: parameters and symmetric primitives are being ported.
"""

from .parameters import HQC_1, HQC_3, HQC_5, get_parameters
from .kem import hqc_kem_keypair, hqc_kem_encaps, hqc_kem_decaps
from .pke import hqc_pke_keygen, hqc_pke_encrypt, hqc_pke_decrypt

__all__ = [
	"HQC_1",
	"HQC_3",
	"HQC_5",
	"get_parameters",
	"hqc_kem_keypair",
	"hqc_kem_encaps",
	"hqc_kem_decaps",
	"hqc_pke_keygen",
	"hqc_pke_encrypt",
	"hqc_pke_decrypt",
]
