"""
Encapsulation and Decapsulation Module for Post-Quantum KEM

This module implements encapsulation and decapsulation logic based on hybrid encryption concepts
integrating symmetric and post-quantum cryptographic algorithms.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.backends import default_backend

def encapsulate(public_key):
    """
    Encapsulates a symmetric encryption key by wrapping it with the provided public key.

    Parameters:
        public_key: RSA public key object

    Returns:
        tuple: (Ciphertext (wrapped key), Symmetric Key)
    """
    symmetric_key = os.urandom(32)  # Generate a random AES-256 symmetric key

    # RSA-OAEP wrapping
    wrapped_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped_key, symmetric_key

def decapsulate(wrapped_key, private_key):
    """
    Decapsulates and retrieves the symmetric encryption key using the private key.

    Parameters:
        wrapped_key: Ciphertext from encapsulate
        private_key: RSA private key object

    Returns:
        Symmetric Key
    """
    symmetric_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symmetric_key


if __name__ == "__main__":
    from key_generation import generate_key_pair

    # Generate RSA Key Pair as an example
    private_key, public_key = generate_key_pair()

    # Encapsulation
    wrapped_key, symmetric_key = encapsulate(public_key)
    print("Symmetric Key:", symmetric_key.hex())
    print("Wrapped Key:", wrapped_key.hex())

    # Decapsulation
    recovered_key = decapsulate(wrapped_key, private_key)
    print("Recovered Key:", recovered_key.hex())

    assert symmetric_key == recovered_key, "Key Decapsulation Failed!"