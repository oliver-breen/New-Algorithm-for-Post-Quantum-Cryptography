# New Algorithm for Post-Quantum Cryptography

A Python implementation of lattice-based post-quantum cryptographic systems designed to be secure against quantum computer attacks.

## 🔐 Overview

This project implements multiple post-quantum cryptographic schemes:
- **Custom LWE-based encryption**: A novel post-quantum encryption scheme based on the **Learning With Errors (LWE)** problem
- **Kyber KEM**: NIST-standardized key encapsulation mechanism
- **Dilithium Signatures**: NIST-standardized digital signature scheme  
- **Saber KEM**: Module lattice-based key encapsulation mechanism

All algorithms provide quantum-resistant security with multiple security levels.

## ✨ Key Features

- **Quantum-Resistant Security**: Based on hard lattice problems
- **Multiple Algorithms**: Custom LWE, Kyber, Dilithium, and Saber implementations
- **Multiple Security Levels**: 128-bit, 192-bit, and 256-bit security options
- **Pure Python Implementation**: No external dependencies for core functionality
- **Simple API**: Easy-to-use interface for developers
- **Comprehensive Testing**: Full test suite included
- **Well-Documented**: Extensive documentation and examples

## 🚀 Quick Start

### Custom LWE-based Encryption

```python
from pqcrypto import PQCrypto

# Initialize the system
pqc = PQCrypto(security_level='LEVEL1')

# Generate keys
public_key, private_key = pqc.generate_keypair()

# Encrypt a message
message = b"Hello, Quantum World!"
ciphertext = pqc.encrypt(message, public_key)

# Decrypt
plaintext = pqc.decrypt(ciphertext, private_key)
print(plaintext)  # b'Hello, Quantum World!'
```

### NIST-Standard Algorithms

```python
from pqcrypto.kyber_dilithium_saber import KyberKEM, DilithiumSignature, SaberKEM

# Kyber Key Encapsulation
kyber = KyberKEM('Kyber768')
pk, sk = kyber.generate_keypair()
shared_secret, ciphertext = kyber.encapsulate(pk)
recovered_secret = kyber.decapsulate(ciphertext, sk)

# Dilithium Digital Signatures
dilithium = DilithiumSignature('Dilithium3')
pk, sk = dilithium.generate_keypair()
signature = dilithium.sign(b"Message", sk)
is_valid = dilithium.verify(b"Message", signature, pk)

# Saber Key Encapsulation
saber = SaberKEM('Saber')
pk, sk = saber.generate_keypair()
shared_secret, ciphertext = saber.encapsulate(pk)
recovered_secret = saber.decapsulate(ciphertext, sk)
```

## 📚 Documentation

- [Custom Algorithm Details](docs/ALGORITHM.md) - LWE-based algorithm description
- [Kyber, Dilithium & Saber Documentation](docs/algo_docs.md) - Detailed NIST algorithm documentation
- [API Reference](docs/ALGORITHM.md#api-reference) - Complete API documentation
- [Security Analysis](docs/SECURITY.md) - Security considerations and threat model
- [Test Results](results_v2.md) - Baseline test results

## 🧪 Running Tests

```bash
# Test custom LWE implementation
python -m unittest tests/test_pqcrypto.py -v

# Test Kyber, Dilithium, and Saber
python -m unittest tests/test_crypto.py -v

# Run all tests
python -m unittest discover tests -v
```

## 📊 Examples

```bash
# Basic usage demonstration
python examples/basic_usage.py

# Performance benchmarks
python examples/benchmark.py
```

## 🏗️ Project Structure

```
├── pqcrypto/                      # Main library
│   ├── core.py                    # Main API for custom LWE
│   ├── keygen.py                  # Key generation
│   ├── encryption.py              # Encryption/decryption
│   ├── math_utils.py              # Mathematical utilities
│   ├── parameters.py              # Security parameters
│   └── kyber_dilithium_saber.py   # NIST algorithms (Kyber, Dilithium, Saber)
├── tests/                         # Test suite
│   ├── test_pqcrypto.py          # Tests for custom LWE implementation
│   └── test_crypto.py            # Tests for Kyber, Dilithium, Saber
├── examples/                      # Usage examples
├── docs/                          # Documentation
│   ├── ALGORITHM.md              # Custom LWE algorithm details
│   ├── algo_docs.md              # Kyber, Dilithium, Saber documentation
│   └── SECURITY.md               # Security analysis
└── results_v2.md                 # Test results
```

## 🔬 Algorithm Design

The algorithm uses:
- **Polynomial Ring**: R_q = Z_q[X]/(X^n + 1)
- **LWE Problem**: Hard problem forming security foundation
- **Centered Binomial Sampling**: For generating secure noise
- **Compression**: To reduce ciphertext size

See [Algorithm Details](docs/ALGORITHM.md) for more information.

## ⚠️ Security Notice

This is an **educational implementation**. For production use:

1. Use NIST-standardized algorithms (Kyber, Dilithium)
2. Obtain professional security audits
3. Implement constant-time operations
4. Consider side-channel attack resistance

**DO NOT USE IN PRODUCTION WITHOUT PROFESSIONAL SECURITY REVIEW**

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 👤 Author

Oliver Breen

## 🤝 Contributing

Contributions are welcome! Please ensure all tests pass and documentation is updated.