"""
QuantaWeave Post-Quantum Cryptography Library.

A lattice-based post-quantum cryptography implementation using the
Learning With Errors (LWE) problem.
"""

__version__ = "0.1.0"
__author__ = "Oliver Breen"

from .core import QuantaWeave
from .keygen import KeyGenerator
from .encryption import Encryptor, Decryptor
from .hqc import hqc_kem_keypair, hqc_kem_encaps, hqc_kem_decaps
from .falcon import FalconSig

__all__ = [
	'QuantaWeave',
	'KeyGenerator',
	'Encryptor',
	'Decryptor',
	'hqc_kem_keypair',
	'hqc_kem_encaps',
	'hqc_kem_decaps',
	'FalconSig',
]
