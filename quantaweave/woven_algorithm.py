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
from .pq_schemes import UnifiedPQHybrid, KyberScheme, HQCScheme, FalconScheme

class QuantaWeaveAlgorithm(PQScheme):
    def hybrid_encrypt(self, public_key: bytes, plaintext: bytes) -> tuple:
        """
        Hybrid encrypt: derive shared secret via KEMs, then encrypt plaintext with AES-GCM using the combined secret.
        Returns (ciphertext_dict, aes_gcm_dict)
        """
        try:
            pub_key_obj = pickle.loads(public_key)
        except Exception:
            pub_key_obj = public_key
        result = self.hybrid.encapsulate(pub_key_obj, plaintext=plaintext)
        return result["ct"], result["aes_gcm"]

    def hybrid_decrypt(self, ciphertext: dict, secret_key: bytes, aes_gcm: dict) -> bytes:
        """
        Hybrid decrypt: derive shared secret via KEMs, then decrypt AES-GCM ciphertext using the combined secret.
        """
        try:
            sec_key_obj = pickle.loads(secret_key)
        except Exception:
            sec_key_obj = secret_key
        plaintext = self.hybrid.decapsulate(ciphertext, sec_key_obj, aes_gcm=aes_gcm)
        return plaintext
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Hybrid sign using all signature schemes (e.g., Dilithium, Falcon)."""
        # For hybrid, secret_key is a pickled list if multiple schemes, else raw bytes
        if isinstance(secret_key, bytes):
            try:
                sec_keys_list = pickle.loads(secret_key)
            except Exception:
                sec_keys_list = [secret_key]
        else:
            sec_keys_list = secret_key
        sigs = self.hybrid.sign(message, sec_keys_list)
        # For single-scheme, return raw bytes; for hybrid, pickle the list
        return sigs[0] if len(sigs) == 1 else pickle.dumps(sigs)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Hybrid verify using all signature schemes (e.g., Dilithium, Falcon)."""
        # For hybrid, signature and public_key may be pickled lists
        if isinstance(signature, bytes):
            try:
                sigs = pickle.loads(signature)
            except Exception:
                sigs = [signature]
        else:
            sigs = signature
        if isinstance(public_key, bytes):
            try:
                pub_keys_list = pickle.loads(public_key)
            except Exception:
                pub_keys_list = [public_key]
        else:
            pub_keys_list = public_key
        return self.hybrid.verify(message, sigs, pub_keys_list)

    def __init__(self):
        # True hybrid: RSA-GCM, ML-KEM (Kyber), ML-DSA (Dilithium), HQC, Falcon
        from quantaweave.pq_schemes import HQCScheme, RSAGCMScheme, DilithiumScheme
        self.hybrid = UnifiedPQHybrid(
            kem_schemes=[
                RSAGCMScheme(),
                KyberScheme(),
                HQCScheme()
            ],
            sig_schemes=[
                FalconScheme(),
                DilithiumScheme()
            ]
        )

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a unified public/secret key pair for the Woven algorithm.
        Returns raw bytes for single-scheme (Kyber, Dilithium).
        For hybrid, serialize as a dict mapping scheme name to key to preserve key integrity.
        """
        pub_keys_list, sec_keys_list = self.hybrid.generate_keypair()
        if len(pub_keys_list) == 1:
            pub_key_blob = pub_keys_list[0]
        else:
            # Use explicit, stable scheme identifiers
            scheme_ids = ["Kyber", "HQC", "Falcon"][:len(pub_keys_list)]
            pub_key_dict = {name: key for name, key in zip(scheme_ids, pub_keys_list)}
            pub_key_blob = pickle.dumps(pub_key_dict)
        if len(sec_keys_list) == 1:
            sec_key_blob = sec_keys_list[0]
        else:
            scheme_ids = ["Kyber", "HQC", "Falcon"][:len(sec_keys_list)]
            sec_key_dict = {name: key for name, key in zip(scheme_ids, sec_keys_list)}
            sec_key_blob = pickle.dumps(sec_key_dict)
        return pub_key_blob, sec_key_blob

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the Woven algorithm (Kyber).
        For hybrid, unpickle as dict and preserve order by scheme.
        """
        try:
            pub_key_obj = pickle.loads(public_key)
            if isinstance(pub_key_obj, dict):
                scheme_ids = ["Kyber", "HQC", "Falcon"][:len(pub_key_obj)]
                pub_keys_list = [pub_key_obj[name] for name in scheme_ids]
            else:
                pub_keys_list = pub_key_obj
        except Exception:
            pub_keys_list = [public_key]
        ciphertexts_list, shared_secret = self.hybrid.encapsulate(pub_keys_list)
        if len(ciphertexts_list) == 1:
            ciphertext_blob = ciphertexts_list[0]
        else:
            ciphertext_blob = pickle.dumps(ciphertexts_list)
        return ciphertext_blob, shared_secret

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """
        Decapsulate the shared secret using the Woven algorithm.
        Always use the original 2400-byte Kyber secret key from keygen if available.
        For hybrid, unpickle as dict and preserve order by scheme.
        """
        try:
            ciphertexts_list = pickle.loads(ciphertext)
        except Exception:
            ciphertexts_list = [ciphertext]
        try:
            sec_key_obj = pickle.loads(secret_key)
            if isinstance(sec_key_obj, dict):
                scheme_ids = ["Kyber", "HQC", "Falcon"][:len(sec_key_obj)]
                sec_keys_list = [sec_key_obj[name] for name in scheme_ids]
            else:
                sec_keys_list = sec_key_obj
        except Exception:
            sec_keys_list = [secret_key]
        result = self.hybrid.decapsulate(ciphertexts_list, sec_keys_list)
        return result

    # Signature methods removed for Kyber-only testing
