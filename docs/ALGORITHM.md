# Post-Quantum Cryptography Algorithm

A Python implementation of a lattice-based post-quantum cryptography algorithm using the Learning With Errors (LWE) problem.

## Overview

This library implements a quantum-resistant encryption scheme designed to be secure against attacks from both classical and quantum computers. The algorithm is based on the hardness of the Learning With Errors (LWE) problem, which is believed to be hard even for quantum computers.

## Features

- **Quantum-Resistant**: Based on lattice problems that are hard for quantum computers
- **Multiple Security Levels**: Support for 128-bit, 192-bit, and 256-bit security
- **Simple API**: Easy-to-use interface for key generation, encryption, and decryption
- **Pure Python**: No external dependencies for core functionality
- **Well-Tested**: Comprehensive test suite

## Algorithm Description

### Mathematical Foundation

The algorithm is based on the **Learning With Errors (LWE)** problem:

Given pairs (A, b) where b = As + e (mod q), it is computationally hard to recover the secret vector s, even with access to many such pairs.

### Key Components

1. **Polynomial Ring**: Operations are performed in R_q = Z_q[X]/(X^n + 1)
2. **Key Generation**: 
   - Secret key: s sampled from centered binomial distribution
   - Public key: (A, b) where b = As + e
3. **Encryption**: 
   - Ciphertext: (u, v) where u = Ar + e1 and v = br + e2 + encode(m)
4. **Decryption**: 
   - Message: decode(v - us)

### Security Levels

| Level | Dimension (n) | Modulus (q) | Security Bits |
|-------|---------------|-------------|---------------|
| LEVEL1 | 256 | 3329 | 128 |
| LEVEL3 | 512 | 7681 | 192 |
| LEVEL5 | 1024 | 12289 | 256 |

## Installation

Since this is a self-contained library, simply copy the `pqcrypto` directory to your project:

```bash
git clone https://github.com/oliver-breen/New-Algorithm-for-Post-Quantum-Cryptography.git
cd New-Algorithm-for-Post-Quantum-Cryptography
```

## Usage

### Basic Example

```python
from pqcrypto import PQCrypto

# Initialize with desired security level
pqc = PQCrypto(security_level='LEVEL1')

# Generate key pair
public_key, private_key = pqc.generate_keypair()

# Encrypt a message
message = b"Hello, Quantum World!"
ciphertext = pqc.encrypt(message, public_key)

# Decrypt the ciphertext
decrypted = pqc.decrypt(ciphertext, private_key)

assert message == decrypted
```

### Advanced Example

```python
from pqcrypto import PQCrypto

# Use higher security level for sensitive data
pqc = PQCrypto(security_level='LEVEL5')  # 256-bit security

public_key, private_key = pqc.generate_keypair()

# Encrypt binary data
data = bytes([0x48, 0x65, 0x6c, 0x6c, 0x6f])
ciphertext = pqc.encrypt(data, public_key)

# Decrypt
plaintext = pqc.decrypt(ciphertext, private_key)
print(plaintext)  # b'Hello'
```

## Running Examples

```bash
# Basic usage example
python examples/basic_usage.py

# Performance benchmark
python examples/benchmark.py
```

## Running Tests

```bash
# Run all tests
python -m unittest tests/test_pqcrypto.py

# Run specific test class
python -m unittest tests.test_pqcrypto.TestEncryptionDecryption

# Run with verbose output
python -m unittest tests/test_pqcrypto.py -v
```

## API Reference

### PQCrypto Class

Main interface for the cryptography system.

#### Methods

- `__init__(security_level='LEVEL1')`: Initialize with security level
- `generate_keypair()`: Generate public and private key pair
- `encrypt(message, public_key)`: Encrypt a message
- `decrypt(ciphertext, private_key)`: Decrypt a ciphertext
- `get_security_level()`: Get security level in bits

### KeyGenerator Class

Handles key pair generation.

#### Methods

- `__init__(security_level='LEVEL1')`: Initialize key generator
- `generate_keypair()`: Generate a key pair
- `get_security_level()`: Get security level in bits

### Encryptor Class

Handles message encryption.

#### Methods

- `__init__(public_key)`: Initialize with public key
- `encrypt(message)`: Encrypt a message (max length n/8 bytes)

### Decryptor Class

Handles ciphertext decryption.

#### Methods

- `__init__(private_key)`: Initialize with private key
- `decrypt(ciphertext)`: Decrypt a ciphertext

## Security Considerations

### Strengths

1. **Quantum Resistance**: Based on lattice problems believed to be hard for quantum computers
2. **Provable Security**: Security can be reduced to well-studied hard problems
3. **Efficient**: Polynomial operations are relatively fast

### Limitations

1. **Message Length**: Limited by polynomial dimension (n/8 bytes)
2. **Ciphertext Size**: Larger than classical schemes like RSA
3. **Error Tolerance**: Small probability of decryption errors

### Best Practices

1. Use LEVEL3 or LEVEL5 for highly sensitive data
2. Regularly rotate keys
3. Combine with authenticated encryption in production systems
4. Keep private keys secure and never transmit them

## Performance

Approximate performance on modern hardware (single core):

| Operation | LEVEL1 | LEVEL3 | LEVEL5 |
|-----------|--------|--------|--------|
| Key Generation | ~10ms | ~40ms | ~150ms |
| Encryption | ~10ms | ~40ms | ~150ms |
| Decryption | ~10ms | ~40ms | ~150ms |

*Note: These are estimates for the pure Python implementation. Performance varies by hardware.*

## Implementation Details

### Polynomial Operations

- **Addition/Subtraction**: O(n) coefficient-wise operations
- **Multiplication**: O(n²) using naive algorithm (can be optimized with NTT)
- **Modular Reduction**: Reduction modulo X^n + 1

### Sampling

- **Uniform Sampling**: Uses cryptographically secure random number generator
- **Centered Binomial**: Generates small errors for security
- **Error Distribution**: Carefully calibrated to balance security and correctness

### Compression

- Ciphertexts are compressed to reduce size
- Compression parameters (du, dv) balance size and decryption accuracy

## Future Enhancements

Potential improvements for future versions:

1. **NTT Optimization**: Implement Number Theoretic Transform for O(n log n) multiplication
2. **Batch Operations**: Support encrypting multiple messages efficiently
3. **Key Serialization**: Add methods to save/load keys
4. **Side-Channel Resistance**: Add constant-time implementations
5. **Digital Signatures**: Implement signature schemes
6. **Key Exchange**: Add key encapsulation mechanism (KEM)

## References

This implementation is inspired by:

1. Regev, O. (2005). "On lattices, learning with errors, random linear codes, and cryptography"
2. NIST Post-Quantum Cryptography Standardization
3. Kyber: A CCA-secure module-lattice-based KEM
4. Dilithium: A lattice-based digital signature scheme

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. Code follows existing style
3. New features include tests
4. Documentation is updated

## Author

Oliver Breen

## Disclaimer

This is an educational implementation. For production use, consider:

1. Using NIST-standardized algorithms (Kyber, Dilithium)
2. Professional security audits
3. Constant-time implementations
4. Side-channel attack resistance

**DO NOT USE IN PRODUCTION WITHOUT PROFESSIONAL SECURITY REVIEW**
