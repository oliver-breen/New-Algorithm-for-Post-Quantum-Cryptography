"""
The "QuantaWeave" Algorithm: A Robust Hybrid Post-Quantum Scheme.

This module weaves together multiple post-quantum primitives into a single, cohesive algorithm.
It combines:
- Kyber-768 (Lattice-based KEM) for efficient key encapsulation.
- HQC-128 (Code-based KEM) for redundancy against lattice-specific attacks.
- Dilithium-3 (Lattice-based Signature) for authenticated key exchange.

This hybrid approach ensures that the system remains secure even if one of the underlying
mathematical problems (Lattice or Code-based) is compromised.
"""

import pickle
from typing import Tuple, Any, List
from .pq_unified_interface import PQScheme
from .pq_schemes import UnifiedPQHybrid, KyberScheme, HQCScheme, DilithiumScheme, FalconScheme

class QuantaWeaveAlgorithm(PQScheme):
    """
    The concrete implementation of the QuantaWeave hybrid algorithm.
    """
    
    def __init__(self):
        # Weave together Kyber, HQC, Dilithium, and Falcon
        self.hybrid = UnifiedPQHybrid(
            kem_schemes=[
                KyberScheme(),          # Primary Lattice KEM
                HQCScheme(param_set="HQC-1") # Secondary Code-based KEM (Redundancy)
            ],
            sig_schemes=[
                DilithiumScheme(),      # Primary Lattice Signature
                FalconScheme(param_set="Falcon-1024") # Secondary Lattice Signature (Compact)
            ]
        )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a unified public/secret key pair for the Woven algorithm.
        Returns serialized (pickled) bytes.
        """
        # Generate keys for all sub-schemes
        pub_keys_list, sec_keys_list = self.hybrid.generate_keypair()
        
        # Serialize to single blobs
        pub_key_blob = pickle.dumps(pub_keys_list)
        sec_key_blob = pickle.dumps(sec_keys_list)
        
        return pub_key_blob, sec_key_blob

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the Woven algorithm (Kyber + HQC).
        """
        # Deserialize public key list
        try:
            pub_keys_list = pickle.loads(public_key)
        except Exception:
            raise ValueError("Invalid public key format")
            
        # Hybrid Encapsulation
        ciphertexts_list, shared_secret = self.hybrid.encapsulate(pub_keys_list)
        
        # Serialize ciphertext list
        ciphertext_blob = pickle.dumps(ciphertexts_list)
        
        return ciphertext_blob, shared_secret

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate the shared secret using the Woven algorithm.
        """
        try:
            ciphertexts_list = pickle.loads(ciphertext)
            sec_keys_list = pickle.loads(secret_key)
        except Exception:
            raise ValueError("Invalid ciphertext or secret key format")
            
        return self.hybrid.decapsulate(ciphertexts_list, sec_keys_list)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message using the Woven algorithm (Dilithium).
        """
        try:
            sec_keys_list = pickle.loads(secret_key)
        except Exception:
            raise ValueError("Invalid secret key format")
            
        signatures_list = self.hybrid.sign(message, sec_keys_list)
        return pickle.dumps(signatures_list)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature using the Woven algorithm.
        """
        try:
            signatures_list = pickle.loads(signature)
            pub_keys_list = pickle.loads(public_key)
        except Exception:
            return False
            
        return self.hybrid.verify(message, signatures_list, pub_keys_list)
