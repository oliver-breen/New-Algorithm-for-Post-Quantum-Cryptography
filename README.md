# New Algorithm for Post-Quantum Cryptography

A Python implementation of a lattice-based post-quantum cryptographic system designed to be secure against quantum computer attacks.

## 🔐 Overview

This project implements a novel post-quantum encryption scheme based on the **Learning With Errors (LWE)** problem, which is believed to be hard even for quantum computers. The algorithm provides quantum-resistant encryption with multiple security levels.

## ✨ Key Features

- **Quantum-Resistant Security**: Based on hard lattice problems
- **Multiple Security Levels**: 128-bit, 192-bit, and 256-bit security options
- **Pure Python Implementation**: No external dependencies for core functionality
- **Simple API**: Easy-to-use interface for developers
- **Comprehensive Testing**: Full test suite included
- **Well-Documented**: Extensive documentation and examples

## 🚀 Quick Start

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

## 📚 Documentation

- [Algorithm Details](docs/ALGORITHM.md) - Comprehensive algorithm description
- [API Reference](docs/ALGORITHM.md#api-reference) - Complete API documentation
- [Security Analysis](docs/ALGORITHM.md#security-considerations) - Security considerations

## 🧪 Running Tests

```bash
python -m unittest tests/test_pqcrypto.py -v
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
├── pqcrypto/           # Main library
│   ├── core.py         # Main API
│   ├── keygen.py       # Key generation
│   ├── encryption.py   # Encryption/decryption
│   ├── math_utils.py   # Mathematical utilities
│   └── parameters.py   # Security parameters
├── tests/              # Test suite
├── examples/           # Usage examples
└── docs/               # Documentation
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