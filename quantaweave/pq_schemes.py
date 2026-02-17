
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
        self.pk = None
        self.sk = None

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        pk, sk = kyber_keygen()
        print(f"[DEBUG Kyber] generate_keypair: pk={pk}, sk={sk}")
        assert isinstance(pk, bytes) and isinstance(sk, bytes)
        self.pk = pk
        self.sk = sk  # Store original 2400-byte secret key
        return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        assert isinstance(public_key, bytes)
        ct, ss = kyber_encaps(public_key)
        print(f"[DEBUG Kyber] encapsulate: pk={public_key}, ct={ct}, ss={ss}")
        assert isinstance(ct, bytes) and isinstance(ss, bytes)
        self.ct = ct
        self.ss = ss
        return ct, ss

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        assert isinstance(ciphertext, bytes)
        # Always use the original 2400-byte secret key from keygen for decapsulation
        sk = self.sk if (hasattr(self, 'sk') and isinstance(self.sk, bytes) and len(self.sk) == 2400) else secret_key
        assert isinstance(sk, bytes) and len(sk) == 2400
        ss = kyber_decaps(ciphertext, sk)
        print(f"[DEBUG Kyber] decapsulate: ct={ciphertext}, sk={sk}, ss={ss}")
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

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        pk, sk = hqc_kem_keypair(self.params)
        assert isinstance(pk, bytes) and isinstance(sk, bytes)
        return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        ct, ss = hqc_kem_encaps(self.params, public_key)
        assert isinstance(ct, bytes) and isinstance(ss, bytes)
        return ct, ss

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        ss = hqc_kem_decaps(self.params, ciphertext, secret_key)
        assert isinstance(ss, bytes)
        return ss

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        # HQC does not support signatures
        raise NotImplementedError("HQC does not support signatures.")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        # HQC does not support signatures
        raise NotImplementedError("HQC does not support signatures.")


# Use the Falcon implementation (or mock/backend)


import pickle
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
except ImportError:
    AES = None
    get_random_bytes = None
try:
    from pqcrypto.dsa import dilithium3
except ImportError:
    dilithium3 = None
from .falcon import FalconSig
from .dilithium_bindings import DilithiumC
from .rsa_gcm import RSAGCM

class FalconScheme(PQScheme):
    def __init__(self, param_set: str = "Falcon-1024"):
        self.falcon = FalconSig(param_set)

    def generate_keypair(self) -> tuple:
        return self.falcon.keygen()

    def encapsulate(self, public_key: any) -> tuple:
        # Falcon does not support KEM
        raise NotImplementedError("Falcon does not support KEM.")

    def decapsulate(self, ciphertext: any, secret_key: any) -> any:
        # Falcon does not support KEM
        raise NotImplementedError("Falcon does not support KEM.")

    def sign(self, message: bytes, secret_key: any) -> any:
        return self.falcon.sign(secret_key, message)

    def verify(self, message: bytes, signature: any, public_key: any) -> bool:
        return self.falcon.verify(public_key, message, signature)
class DilithiumScheme(PQScheme):
    def __init__(self):
        self.dilithium = DilithiumC()

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return self.dilithium.keypair()

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        raise NotImplementedError("Dilithium does not support KEM.")

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        raise NotImplementedError("Dilithium does not support KEM.")

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        return self.dilithium.sign(message, secret_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        # The binding expects the signed message, so we must re-sign and compare, or adapt as needed
        return self.dilithium.verify(signature, public_key)

class RSAGCMScheme(PQScheme):
    def __init__(self, key_size=2048):
        self.rsa = RSAGCM(key_size)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return self.rsa.generate_keypair()

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        # For KEM, encrypt a random secret
        import os
        secret = os.urandom(32)
        enc_dict = self.rsa.encrypt(secret, public_key)
        return (pickle.dumps(enc_dict), secret)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        enc_dict = pickle.loads(ciphertext)
        return self.rsa.decrypt(enc_dict, secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        raise NotImplementedError("RSA-GCM does not support signatures.")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        raise NotImplementedError("RSA-GCM does not support signatures.")

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
    def _get_scheme_id(self, scheme):
        # Map scheme object to its stable identifier
        if isinstance(scheme, KyberScheme):
            return "Kyber"
        elif isinstance(scheme, HQCScheme):
            return "HQC"
        elif isinstance(scheme, FalconScheme):
            return "Falcon"
        elif isinstance(scheme, DilithiumScheme):
            return "Dilithium"
        elif isinstance(scheme, RSAGCMScheme):
            return "RSA-GCM"
        else:
            return type(scheme).__name__

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

    def encapsulate(self, public_keys, plaintext: bytes = b"") -> dict:
        # Accept dict or list for public_keys
        # Optionally encrypt a plaintext using AES-GCM with the combined secret
        if AES is None or get_random_bytes is None:
            raise ImportError("pycryptodome is not installed.")
        scheme_ids = [self._get_scheme_id(s) for s in self.kem_schemes]
        if isinstance(public_keys, dict):
            pk_map = public_keys
        else:
            pk_map = {name: key for name, key in zip(scheme_ids, public_keys)}
        ciphertexts = {}
        shared_secrets = []
        for i, scheme in enumerate(self.kem_schemes):
            scheme_id = scheme_ids[i]
            pk = pk_map[scheme_id]
            assert isinstance(pk, bytes)
            print(f"[DEBUG] Encapsulate: scheme={type(scheme).__name__}, pk type={type(pk)}, pk={pk}")
            ct, ss = scheme.encapsulate(pk)
            assert isinstance(ct, bytes) and isinstance(ss, bytes)
            ciphertexts[scheme_id] = ct
            shared_secrets.append(ss)
        print("[DEBUG] Encapsulate: shared_secrets:", shared_secrets)
        combined_secret = self.secret_combiner(shared_secrets)
        print("[DEBUG] Encapsulate: combined_secret:", combined_secret)
        # AES-GCM encryption (if plaintext provided)
        aes_result = None
        if plaintext:
            key = combined_secret[:32]  # AES-256
            nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            ct_bytes, tag = cipher.encrypt_and_digest(plaintext)
            aes_result = {"nonce": nonce, "ciphertext": ct_bytes, "tag": tag}
        return {"ct": ciphertexts, "combined_secret": combined_secret, "aes_gcm": aes_result}

    def decapsulate(self, ciphertexts, secret_keys, aes_gcm: dict = None) -> bytes:
        # Accept dict or list for ciphertexts and secret_keys
        # Optionally decrypt AES-GCM if aes_gcm dict provided
        if AES is None:
            raise ImportError("pycryptodome is not installed.")
        scheme_ids = ["Kyber", "HQC", "Falcon"][:len(self.kem_schemes + self.sig_schemes)]
        if isinstance(ciphertexts, dict):
            ct_map = ciphertexts
        else:
            ct_map = {name: ct for name, ct in zip(scheme_ids, ciphertexts)}
        if isinstance(secret_keys, dict):
            sk_map = secret_keys
        else:
            sk_map = {name: sk for name, sk in zip(scheme_ids, secret_keys)}
        shared_secrets = []
        for i, scheme in enumerate(self.kem_schemes):
            scheme_id = scheme_ids[i]
            ct = ct_map[scheme_id]
            sk = sk_map[scheme_id]
            # For Kyber, always ensure the secret key is 2400 bytes (original from keygen)
            if type(scheme).__name__ == "KyberScheme":
                if hasattr(scheme, 'sk') and isinstance(scheme.sk, bytes) and len(scheme.sk) == 2400:
                    sk = scheme.sk
                elif not (isinstance(sk, bytes) and len(sk) == 2400):
                    raise ValueError("Kyber decapsulation requires the original 2400-byte secret key from keygen. Got key of length {}.".format(len(sk) if isinstance(sk, bytes) else type(sk)))
            assert isinstance(ct, bytes) and isinstance(sk, bytes)
            print(f"[DEBUG] Decapsulate: scheme={type(scheme).__name__}, ct type={type(ct)}, sk type={type(sk)}, sk len={len(sk)}")
            ss = scheme.decapsulate(ct, sk)
            assert isinstance(ss, bytes)
            shared_secrets.append(ss)
        print("[DEBUG] Decapsulate: shared_secrets:", shared_secrets)
        combined_secret = self.secret_combiner(shared_secrets)
        print("[DEBUG] Decapsulate: combined_secret:", combined_secret)
        # AES-GCM decryption (if aes_gcm provided)
        if aes_gcm:
            key = combined_secret[:32]
            cipher = AES.new(key, AES.MODE_GCM, nonce=aes_gcm["nonce"])
            plaintext = cipher.decrypt_and_verify(aes_gcm["ciphertext"], aes_gcm["tag"])
            return plaintext
        return combined_secret

    def sign(self, message: bytes, secret_keys) -> list:
        assert isinstance(message, bytes)
        # Accept dict or list for secret_keys
        if isinstance(secret_keys, dict):
            scheme_ids = [self._get_scheme_id(s) for s in self.sig_schemes]
            secret_keys = [secret_keys[k] for k in scheme_ids]
        signatures = []
        for scheme, sk in zip(self.sig_schemes, secret_keys):
            assert isinstance(sk, bytes)
            print(f"[DEBUG] Sign: scheme={type(scheme).__name__}, sk type={type(sk)}, msg type={type(message)}")
            sig = scheme.sign(message, sk)
            assert isinstance(sig, bytes)
            signatures.append(sig)
        print("[DEBUG] Sign: signatures:", signatures)
        return signatures

    def verify(self, message: bytes, signatures, public_keys) -> bool:
        assert isinstance(message, bytes)
        # Accept dict or list for signatures/public_keys
        if isinstance(signatures, dict):
            scheme_ids = [self._get_scheme_id(s) for s in self.sig_schemes]
            signatures = [signatures[k] for k in scheme_ids]
        if isinstance(public_keys, dict):
            scheme_ids = [self._get_scheme_id(s) for s in self.sig_schemes]
            public_keys = [public_keys[k] for k in scheme_ids]
        if not isinstance(signatures, list) or not isinstance(public_keys, list):
            raise ValueError("signatures and public_keys must be lists")
        valid_count = 0
        for idx, (scheme, sig, pk) in enumerate(zip(self.sig_schemes, signatures, public_keys)):
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

