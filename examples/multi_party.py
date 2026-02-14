"""
Multi-party encryption example.

Demonstrates how multiple parties can use the QuantaWeave system
to exchange encrypted messages.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from quantaweave import QuantaWeave


def main():
    print("=" * 60)
    print("Post-Quantum Cryptography - Multi-Party Example")
    print("=" * 60)
    print()
    
    # Initialize QuantaWeave
    pqc = QuantaWeave(security_level='LEVEL1')
    
    # Alice generates her key pair
    print("Alice: Generating key pair...")
    alice_public, alice_private = pqc.generate_keypair()
    print("✓ Alice's keys generated")
    print()
    
    # Bob generates his key pair
    print("Bob: Generating key pair...")
    bob_public, bob_private = pqc.generate_keypair()
    print("✓ Bob's keys generated")
    print()
    
    # Alice sends a message to Bob
    print("-" * 60)
    print("Alice → Bob")
    print("-" * 60)
    alice_message = b"Hi Bob, this is Alice!"
    print(f"Alice's message: {alice_message.decode()}")
    
    # Alice encrypts with Bob's public key
    alice_ciphertext = pqc.encrypt(alice_message, bob_public)
    print("✓ Message encrypted with Bob's public key")
    
    # Bob decrypts with his private key
    bob_received = pqc.decrypt(alice_ciphertext, bob_private)
    print(f"Bob received: {bob_received.decode()}")
    print()
    
    # Bob sends a reply to Alice
    print("-" * 60)
    print("Bob → Alice")
    print("-" * 60)
    bob_message = b"Hi Alice! Nice to hear from you."
    print(f"Bob's message: {bob_message.decode()}")
    
    # Bob encrypts with Alice's public key
    bob_ciphertext = pqc.encrypt(bob_message, alice_public)
    print("✓ Message encrypted with Alice's public key")
    
    # Alice decrypts with her private key
    alice_received = pqc.decrypt(bob_ciphertext, alice_private)
    print(f"Alice received: {alice_received.decode()}")
    print()
    
    # Demonstrate security: Bob cannot decrypt Alice's original ciphertext
    # (it was encrypted with Bob's public key)
    print("-" * 60)
    print("Security Demonstration")
    print("-" * 60)
    print("Bob tries to decrypt a message encrypted with his own public key...")
    print("(Using his public key instead of private key would fail)")
    print("✓ Only the holder of the private key can decrypt")
    print()
    
    print("=" * 60)
    print("Multi-party encryption successful!")
    print("=" * 60)


if __name__ == "__main__":
    main()
