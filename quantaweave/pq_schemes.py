
from typing import Optional, List, Tuple, Any
import hashlib
from .pq_unified_interface import PQScheme


from typing import Tuple, Any
# Hybrid/composite PQ algorithm class
from .pq_unified_interface import PQScheme
from .pq_unified_interface import PQScheme


# Import DummyKEM from pqcrypto_suite for placeholder logic

# Use the real Kyber implementation
from kyber_dilithium_hqc import kyber_keygen, kyber_encaps, kyber_decaps

class KyberScheme(PQScheme):
    def __init__(self):
        pass

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        pk, sk = kyber_keygen()
        print(f"[DEBUG Kyber] generate_keypair: pk={pk}, sk={sk}")
        assert isinstance(pk, bytes) and isinstance(sk, bytes)
        # Always return the original 2400-byte secret key
        return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        assert isinstance(public_key, bytes)
        ct, ss = kyber_encaps(public_key)
        print(f"[DEBUG Kyber] encapsulate: pk={public_key}, ct={ct}, ss={ss}")
        assert isinstance(ct, bytes) and isinstance(ss, bytes)
        # No secret key generated here; decapsulate must use original sk from keygen
        return ct, ss

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        assert isinstance(ciphertext, bytes) and isinstance(secret_key, bytes)
        # secret_key must be the original 2400-byte value from generate_keypair
        ss = kyber_decaps(ciphertext, secret_key)
        print(f"[DEBUG Kyber] decapsulate: ct={ciphertext}, sk={secret_key}, ss={ss}")
        assert isinstance(ss, bytes)
        return ss

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        raise NotImplementedError("Kyber does not support signatures.")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        raise NotImplementedError("Kyber does not support signatures.")


# Dilithium and signature logic removed for Kyber-only testing


# Use the real HQC implementation
from quantaweave.hqc.parameters import get_parameters
from quantaweave.hqc.kem import hqc_kem_keypair, hqc_kem_encaps, hqc_kem_decaps

class HQCScheme(PQScheme):
    def __init__(self, param_set: str = "HQC-1"):
        self.params = get_parameters(param_set)

    def generate_keypair(self) -> Tuple[Any, Any]:
        return hqc_kem_keypair(self.params)

    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        return hqc_kem_encaps(self.params, public_key)

    def decapsulate(self, ciphertext: Any, secret_key: Any) -> Any:
        return hqc_kem_decaps(self.params, ciphertext, secret_key)

    def sign(self, message: bytes, secret_key: Any) -> Any:
        # HQC does not support signatures
        raise NotImplementedError("HQC does not support signatures.")

    def verify(self, message: bytes, signature: Any, public_key: Any) -> bool:
        # HQC does not support signatures
        raise NotImplementedError("HQC does not support signatures.")


# Use the Falcon implementation (or mock/backend)
from .falcon import FalconSig

class FalconScheme(PQScheme):
    def __init__(self, param_set: str = "Falcon-1024"):
        self.falcon = FalconSig(param_set)

    def generate_keypair(self) -> Tuple[Any, Any]:
        return self.falcon.keygen()

    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        # Falcon does not support KEM
        raise NotImplementedError("Falcon does not support KEM.")

    def decapsulate(self, ciphertext: Any, secret_key: Any) -> Any:
        # Falcon does not support KEM
        raise NotImplementedError("Falcon does not support KEM.")

    def sign(self, message: bytes, secret_key: Any) -> Any:
        return self.falcon.sign(secret_key, message)

    def verify(self, message: bytes, signature: Any, public_key: Any) -> bool:
        return self.falcon.verify(public_key, message, signature)


class UnifiedPQHybrid(PQScheme):
    def __init__(self, kem_schemes: List[PQScheme], sig_schemes: Optional[List[PQScheme]] = None, secret_combiner=None, sig_threshold: Optional[int] = None):
        self.kem_schemes = kem_schemes
        self.sig_schemes = sig_schemes or []
        # Ensure deterministic combining: sort and hash
        # Deterministic combining: sort by scheme name, then hash
        def default_secret_combiner(secrets, schemes):
            # Normalize secrets to bytes for deterministic combining
            pairs = [(str(type(scheme).__name__), s if isinstance(s, bytes) else bytes(s, 'utf-8'))
                     for scheme, s in zip(schemes, secrets)]
            pairs.sort(key=lambda x: x[0])
            combined = b''.join([p[1] for p in pairs])
            return hashlib.sha3_256(combined).digest()
        self.secret_combiner = secret_combiner or (lambda secrets: default_secret_combiner(secrets, self.kem_schemes))
        # Require all signatures to be valid unless threshold is specified
        self.sig_threshold = sig_threshold if sig_threshold is not None else len(self.sig_schemes)

    def generate_keypair(self) -> Tuple[list, list]:
        pub_keys = []
        sec_keys = []
        for scheme in self.kem_schemes + self.sig_schemes:
            pk, sk = scheme.generate_keypair()
            assert isinstance(pk, bytes) and isinstance(sk, bytes)
            pub_keys.append(pk)
            sec_keys.append(sk)
        return pub_keys, sec_keys

    def encapsulate(self, public_keys: list) -> Tuple[list, bytes]:
        if len(public_keys) < len(self.kem_schemes):
            raise ValueError(f"Expected at least {len(self.kem_schemes)} public keys, got {len(public_keys)}")
        ciphertexts = []
        shared_secrets = []
        for scheme, pk in zip(self.kem_schemes, public_keys[:len(self.kem_schemes)]):
            assert isinstance(pk, bytes)
            print(f"[DEBUG] Encapsulate: scheme={type(scheme).__name__}, pk type={type(pk)}, pk={pk}")
            ct, ss = scheme.encapsulate(pk)
            assert isinstance(ct, bytes) and isinstance(ss, bytes)
            ciphertexts.append(ct)
            shared_secrets.append(ss)
        print("[DEBUG] Encapsulate: shared_secrets:", shared_secrets)
        combined_secret = self.secret_combiner(shared_secrets)
        print("[DEBUG] Encapsulate: combined_secret:", combined_secret)
        return ciphertexts, combined_secret

    def decapsulate(self, ciphertexts: list, secret_keys: list) -> bytes:
        if len(ciphertexts) < len(self.kem_schemes):
            raise ValueError(f"Expected at least {len(self.kem_schemes)} ciphertexts, got {len(ciphertexts)}")
        if len(secret_keys) < len(self.kem_schemes):
            raise ValueError(f"Expected at least {len(self.kem_schemes)} secret keys, got {len(secret_keys)}")
        shared_secrets = []
        for scheme, ct, sk in zip(self.kem_schemes, ciphertexts, secret_keys[:len(self.kem_schemes)]):
            assert isinstance(ct, bytes) and isinstance(sk, bytes)
            print(f"[DEBUG] Decapsulate: scheme={type(scheme).__name__}, ct type={type(ct)}, sk type={type(sk)}")
            ss = scheme.decapsulate(ct, sk)
            assert isinstance(ss, bytes)
            shared_secrets.append(ss)
        print("[DEBUG] Decapsulate: shared_secrets:", shared_secrets)
        combined_secret = self.secret_combiner(shared_secrets)
        print("[DEBUG] Decapsulate: combined_secret:", combined_secret)
        return combined_secret

    def sign(self, message: bytes, secret_keys: list) -> list:
        assert isinstance(message, bytes)
        signatures = []
        for scheme, sk in zip(self.sig_schemes, secret_keys[len(self.kem_schemes):]):
            assert isinstance(sk, bytes)
            print(f"[DEBUG] Sign: scheme={type(scheme).__name__}, sk type={type(sk)}, msg type={type(message)}")
            sig = scheme.sign(message, sk)
            assert isinstance(sig, bytes)
            signatures.append(sig)
        print("[DEBUG] Sign: signatures:", signatures)
        return signatures

    def verify(self, message: bytes, signatures: list, public_keys: list) -> bool:
        assert isinstance(message, bytes)
        if not isinstance(signatures, list) or not isinstance(public_keys, list):
            raise ValueError("signatures and public_keys must be lists")
        valid_count = 0
        for idx, (scheme, sig, pk) in enumerate(zip(self.sig_schemes, signatures, public_keys[len(self.kem_schemes):])):
            assert isinstance(sig, bytes) and isinstance(pk, bytes)
            print(f"[DEBUG] Verify: scheme={type(scheme).__name__}, pk type={type(pk)}, msg type={type(message)}, sig type={type(sig)}")
            try:
                if scheme.verify(message, sig, pk):
                    valid_count += 1
                print(f"[DEBUG] Verify: scheme {idx}, sig valid: {scheme.verify(message, sig, pk)}")
            except Exception:
                continue
        print("[DEBUG] Verify: valid_count:", valid_count)
        return valid_count == len(self.sig_schemes) if self.sig_threshold == len(self.sig_schemes) else valid_count >= self.sig_threshold

