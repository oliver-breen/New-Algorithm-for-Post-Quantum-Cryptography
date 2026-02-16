import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
import pytest
from kyber_dilithium_hqc import kyber_keygen, kyber_encaps, kyber_decaps, dilithium_keygen, dilithium_sign, dilithium_verify

def test_kyber_kem():
    keys = kyber_keygen()
    pk = keys['public_key']
    sk = keys['secret_key']
    encap = kyber_encaps(pk)
    ct = encap['ciphertext']
    ss1 = encap['shared_secret']
    ss2 = kyber_decaps(ct, sk)
    assert ss1 == ss2

def test_dilithium_signature():
    keys = dilithium_keygen()
    pk = keys['public_key']
    sk = keys['secret_key']
    msg = b"test message"
    sig = dilithium_sign(sk, msg)
    assert dilithium_verify(pk, msg, sig)
    # Negative test: tampered message
    assert not dilithium_verify(pk, b"tampered", sig)
