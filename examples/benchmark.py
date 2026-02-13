"""
Performance benchmark for the PQCrypto library.

Tests encryption/decryption speed at different security levels.
"""

import sys
import os
import time

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pqcrypto import PQCrypto


def benchmark_security_level(level, num_iterations=10):
    """Benchmark a specific security level."""
    print(f"\nBenchmarking {level}:")
    print("-" * 50)
    
    pqc = PQCrypto(security_level=level)
    
    # Benchmark key generation
    start_time = time.time()
    for _ in range(num_iterations):
        public_key, private_key = pqc.generate_keypair()
    keygen_time = (time.time() - start_time) / num_iterations
    print(f"  Key generation: {keygen_time*1000:.2f} ms")
    
    # Use last generated key for encryption benchmarks
    message = b"Benchmark test message!"
    
    # Benchmark encryption
    start_time = time.time()
    for _ in range(num_iterations):
        ciphertext = pqc.encrypt(message, public_key)
    encrypt_time = (time.time() - start_time) / num_iterations
    print(f"  Encryption:     {encrypt_time*1000:.2f} ms")
    
    # Benchmark decryption
    start_time = time.time()
    for _ in range(num_iterations):
        decrypted = pqc.decrypt(ciphertext, private_key)
    decrypt_time = (time.time() - start_time) / num_iterations
    print(f"  Decryption:     {decrypt_time*1000:.2f} ms")
    
    # Calculate total time
    total_time = keygen_time + encrypt_time + decrypt_time
    print(f"  Total time:     {total_time*1000:.2f} ms")
    
    return keygen_time, encrypt_time, decrypt_time


def main():
    print("=" * 60)
    print("Post-Quantum Cryptography - Performance Benchmark")
    print("=" * 60)
    
    num_iterations = 10
    print(f"\nRunning {num_iterations} iterations per test...")
    
    # Benchmark all security levels
    results = {}
    for level in ['LEVEL1', 'LEVEL3', 'LEVEL5']:
        results[level] = benchmark_security_level(level, num_iterations)
    
    # Summary
    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)
    print(f"{'Level':<10} {'KeyGen (ms)':<15} {'Encrypt (ms)':<15} {'Decrypt (ms)':<15}")
    print("-" * 60)
    for level in ['LEVEL1', 'LEVEL3', 'LEVEL5']:
        kg, enc, dec = results[level]
        print(f"{level:<10} {kg*1000:<15.2f} {enc*1000:<15.2f} {dec*1000:<15.2f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
