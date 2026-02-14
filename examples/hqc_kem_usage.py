"""
HQC KEM usage example.

Demonstrates key generation, encapsulation, and decapsulation.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from quantaweave import QuantaWeave


def main():
    print("=" * 60)
    print("HQC KEM Example")
    print("=" * 60)
    print()

    pqc = QuantaWeave(security_level='LEVEL1')
    print("Generating HQC keypair...")
    public_key, private_key = pqc.hqc_keypair()
    print(f"✓ Public key length: {len(public_key)} bytes")
    print(f"✓ Private key length: {len(private_key)} bytes")
    print()

    print("Encapsulating shared secret...")
    ciphertext, shared_secret = pqc.hqc_encapsulate(public_key)
    print(f"✓ Ciphertext length: {len(ciphertext)} bytes")
    print(f"✓ Shared secret length: {len(shared_secret)} bytes")
    print()

    print("Decapsulating shared secret...")
    recovered_secret = pqc.hqc_decapsulate(ciphertext, private_key)
    print(f"✓ Match: {shared_secret == recovered_secret}")
    print()

    print("=" * 60)


if __name__ == "__main__":
    main()
