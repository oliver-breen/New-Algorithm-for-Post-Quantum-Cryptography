"""
Basic usage example for the PQCrypto library.

Demonstrates key generation, encryption, and decryption.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pqcrypto import PQCrypto


def main():
    print("=" * 60)
    print("Post-Quantum Cryptography - Basic Example")
    print("=" * 60)
    print()
    
    # Initialize the PQCrypto system with LEVEL1 security (128-bit)
    print("Initializing PQCrypto with 128-bit security level...")
    pqc = PQCrypto(security_level='LEVEL1')
    print(f"Security level: {pqc.get_security_level()} bits")
    print()
    
    # Generate a key pair
    print("Generating key pair...")
    public_key, private_key = pqc.generate_keypair()
    print(f"✓ Public key generated (dimension: {len(public_key['A'])})")
    print(f"✓ Private key generated (dimension: {len(private_key['s'])})")
    print()
    
    # Encrypt a message
    message = b"Hello, Post-Quantum World!"
    print(f"Original message: {message.decode()}")
    print(f"Message length: {len(message)} bytes")
    print()
    
    print("Encrypting message...")
    ciphertext = pqc.encrypt(message, public_key)
    print(f"✓ Ciphertext generated")
    print(f"  - u component length: {len(ciphertext['u'])}")
    print(f"  - v component length: {len(ciphertext['v'])}")
    print()
    
    # Decrypt the ciphertext
    print("Decrypting ciphertext...")
    decrypted_message = pqc.decrypt(ciphertext, private_key)
    print(f"✓ Decrypted message: {decrypted_message.decode()}")
    print()
    
    # Verify correctness
    if message == decrypted_message:
        print("✓ SUCCESS: Message successfully encrypted and decrypted!")
    else:
        print("✗ ERROR: Decryption failed!")
    print()
    
    print("=" * 60)


if __name__ == "__main__":
    main()
