# Detailed Algorithm Documentation

This document provides comprehensive documentation for the post-quantum cryptographic algorithms implemented in this repository: **Kyber**, **Dilithium**, and **Saber**.

## Table of Contents

1. [Kyber: Key Encapsulation Mechanism](#kyber-key-encapsulation-mechanism)
2. [Dilithium: Digital Signature Scheme](#dilithium-digital-signature-scheme)
3. [Saber: Key Encapsulation Mechanism](#saber-key-encapsulation-mechanism)
4. [Security Considerations](#security-considerations)
5. [Performance Characteristics](#performance-characteristics)
6. [Usage Examples](#usage-examples)

---

## Kyber: Key Encapsulation Mechanism

### Overview

**Kyber** is a lattice-based Key Encapsulation Mechanism (KEM) that was selected by NIST as one of the post-quantum cryptography standards. It provides IND-CCA2 security and is based on the Module Learning With Errors (MLWE) problem.

### Security Levels

Kyber offers three security levels corresponding to NIST's security categories:

| Variant | Security Level | Classical Bits | Quantum Bits | Module Rank (k) |
|---------|----------------|----------------|--------------|-----------------|
| Kyber512 | Level 1 | 128 | 64 | 2 |
| Kyber768 | Level 3 | 192 | 96 | 3 |
| Kyber1024 | Level 5 | 256 | 128 | 4 |

### Algorithm Parameters

**Common Parameters:**
- Polynomial degree: n = 256
- Modulus: q = 3329
- Polynomial ring: R_q = Z_q[X]/(X^n + 1)

**Variant-Specific Parameters:**

#### Kyber512
- Module rank: k = 2
- η₁ (noise for key generation): 3
- η₂ (noise for encryption): 2
- d_u (compression parameter for u): 10
- d_v (compression parameter for v): 4

#### Kyber768
- Module rank: k = 3
- η₁: 2
- η₂: 2
- d_u: 10
- d_v: 4

#### Kyber1024
- Module rank: k = 4
- η₁: 2
- η₂: 2
- d_u: 11
- d_v: 5

### Key Generation

**Input:** Random seed

**Output:** Public key (A, t), Secret key (s)

**Algorithm:**
1. Generate secret vector **s** ← CBD_η₁(k) (k polynomials from centered binomial distribution)
2. Generate error vector **e** ← CBD_η₁(k)
3. Generate public matrix **A** ∈ R_q^(k×k) uniformly at random
4. Compute **t** = **A·s** + **e** (mod q)
5. Return pk = (A, t), sk = s

### Encapsulation

**Input:** Public key (A, t)

**Output:** Shared secret K, Ciphertext (u, v)

**Algorithm:**
1. Generate random message m ← {0,1}^256
2. Generate random vectors **r** ← CBD_η₂(k) and **e₁** ← CBD_η₂(k)
3. Generate random polynomial e₂ ← CBD_η₂
4. Compute **u** = **A^T·r** + **e₁** (mod q)
5. Compute v = **t^T·r** + e₂ + Encode(m) (mod q)
6. Derive shared secret K = H(m)
7. Return K, ct = (u, v)

### Decapsulation

**Input:** Ciphertext (u, v), Secret key s

**Output:** Shared secret K

**Algorithm:**
1. Compute m' = Decode(v - **s^T·u**)
2. Re-encrypt to get (u', v') using m' (implicit rejection)
3. If ct = (u', v'), return K = H(m')
4. Otherwise, return K = H(sk||ct) (failure case)

### Mathematical Foundation

The security of Kyber is based on the hardness of the **Module-LWE (MLWE)** problem:

Given (A, b) where:
- A ∈ R_q^(k×k) is uniformly random
- b = A·s + e (mod q) where s, e are small

The problem is to distinguish b from uniform or to recover s.

---

## Dilithium: Digital Signature Scheme

### Overview

**Dilithium** is a lattice-based digital signature scheme selected by NIST for standardization. It provides strong post-quantum security and is based on the hardness of the Module-LWE and Module-SIS problems.

### Security Levels

Dilithium offers three security levels:

| Variant | Security Level | Classical Bits | Quantum Bits | Dimensions (k, l) |
|---------|----------------|----------------|--------------|-------------------|
| Dilithium2 | Level 2 | 128 | 64 | (4, 4) |
| Dilithium3 | Level 3 | 192 | 96 | (6, 5) |
| Dilithium5 | Level 5 | 256 | 128 | (8, 7) |

### Algorithm Parameters

**Common Parameters:**
- Polynomial degree: n = 256
- Modulus: q = 8,380,417
- Polynomial ring: R_q = Z_q[X]/(X^n + 1)

**Variant-Specific Parameters:**

#### Dilithium2
- Dimensions: k = 4, l = 4
- η: 2
- τ: 39
- γ₁: 2^17
- γ₂: (q-1)/88

#### Dilithium3
- Dimensions: k = 6, l = 5
- η: 4
- τ: 49
- γ₁: 2^19
- γ₂: (q-1)/32

#### Dilithium5
- Dimensions: k = 8, l = 7
- η: 2
- τ: 60
- γ₁: 2^19
- γ₂: (q-1)/32

### Key Generation

**Input:** Random seed

**Output:** Public key (A, t), Secret key (s₁, s₂, t)

**Algorithm:**
1. Generate secret vectors **s₁** ← CBD_η(l), **s₂** ← CBD_η(k)
2. Generate public matrix **A** ∈ R_q^(k×l) uniformly at random
3. Compute **t** = **A·s₁** + **s₂** (mod q)
4. Return pk = (A, t), sk = (s₁, s₂, t)

### Signing

**Input:** Message M, Secret key (s₁, s₂, t)

**Output:** Signature σ = (z, c, h)

**Algorithm:**
1. Generate random masking vector **y** ← Uniform([-γ₁, γ₁]^l)
2. Compute **w** = **A·y** (mod q)
3. Compute challenge c = H(M || HighBits(**w**))
4. Compute **z** = **y** + c·**s₁**
5. If ||**z**||∞ ≥ γ₁ - β, restart
6. Compute hint **h** for reconstruction
7. Return σ = (z, c, h)

### Verification

**Input:** Message M, Signature σ = (z, c, h), Public key (A, t)

**Output:** Accept or Reject

**Algorithm:**
1. Parse σ = (z, c, h)
2. Check ||**z**||∞ < γ₁ - β
3. Compute **w'** = **A·z** - c·**t** (mod q)
4. Reconstruct **w'** using hint h
5. Compute c' = H(M || HighBits(**w'**))
6. Accept if c = c', otherwise Reject

### Mathematical Foundation

The security of Dilithium is based on:

1. **Module-LWE**: Hard to recover secret from noisy linear equations
2. **Module-SIS**: Hard to find short vectors in a module lattice

The Fiat-Shamir with Aborts framework provides security against chosen-message attacks.

---

## Saber: Key Encapsulation Mechanism

### Overview

**Saber** is a module lattice-based KEM that was a finalist in the NIST post-quantum cryptography competition. It is based on the Module Learning With Rounding (MLWR) problem, which avoids the need for error sampling.

### Security Levels

Saber offers three security levels:

| Variant | Security Level | Classical Bits | Quantum Bits | Module Rank (l) |
|---------|----------------|----------------|--------------|-----------------|
| LightSaber | Level 1 | 128 | 64 | 2 |
| Saber | Level 3 | 192 | 96 | 3 |
| FireSaber | Level 5 | 256 | 128 | 4 |

### Algorithm Parameters

**Common Parameters:**
- Polynomial degree: n = 256
- Modulus q: 2^13 = 8192
- Rounding modulus p: 2^10 = 1024
- Polynomial ring: R_q = Z_q[X]/(X^n + 1)

**Variant-Specific Parameters:**

#### LightSaber
- Module rank: l = 2
- μ: 10
- ε: 3

#### Saber
- Module rank: l = 3
- μ: 8
- ε: 4

#### FireSaber
- Module rank: l = 4
- μ: 6
- ε: 6

### Key Generation

**Input:** Random seed

**Output:** Public key (A, b), Secret key s

**Algorithm:**
1. Generate secret vector **s** ← CBD_μ(l)
2. Generate public matrix **A** ∈ R_q^(l×l) uniformly at random
3. Compute **b** = ⌊(**A·s**)/p⌋ (rounding operation)
4. Return pk = (A, b), sk = s

### Encapsulation

**Input:** Public key (A, b)

**Output:** Shared secret K, Ciphertext (c, d)

**Algorithm:**
1. Generate random message m ← {0,1}^256
2. Generate random secret **s'** ← CBD_μ(l)
3. Compute **c** = ⌊(**A^T·s'**)/p⌋
4. Compute d = ⌊(**b^T·s'**)/p₂⌋ + Encode(m)
5. Derive shared secret K = H(m)
6. Return K, ct = (c, d)

### Decapsulation

**Input:** Ciphertext (c, d), Secret key s

**Output:** Shared secret K

**Algorithm:**
1. Compute m' = Decode(d - ⌊(**s^T·c**)/p₂⌋)
2. Re-encrypt to verify (implicit rejection)
3. If valid, return K = H(m')
4. Otherwise, return K = H(sk||ct)

### Mathematical Foundation

The security of Saber is based on the **Module-LWR (MLWR)** problem:

Given (A, b) where:
- A ∈ R_q^(l×l) is uniformly random
- b = ⌊A·s/p⌋ where s is small

The problem is to distinguish b from uniform or to recover s.

**Advantage over LWE:** MLWR eliminates the need for discrete Gaussian sampling, making implementation simpler and potentially more resistant to side-channel attacks.

---

## Security Considerations

### General Security Properties

All three algorithms provide:

1. **Post-Quantum Security**: Resistant to attacks from quantum computers
2. **IND-CCA2 Security** (Kyber, Saber): Secure against adaptive chosen-ciphertext attacks
3. **EUF-CMA Security** (Dilithium): Existentially unforgeable under chosen-message attacks

### Attack Resistance

#### Classical Attacks
- **Brute Force**: Infeasible due to large key spaces
- **Algebraic Attacks**: Protected by hardness of lattice problems
- **Meet-in-the-Middle**: Prevented by appropriate parameter choices

#### Quantum Attacks
- **Shor's Algorithm**: Does not apply to lattice problems
- **Grover's Algorithm**: Requires doubling key sizes (already accounted for)
- **Lattice Reduction**: Best known attacks (BKZ) still exponential

### Side-Channel Considerations

**Important for Implementation:**

1. **Constant-Time Operations**: All secret-dependent operations should be constant-time
2. **Masked Operations**: Consider masking for DPA resistance
3. **Fault Attacks**: Implement fault detection mechanisms
4. **Cache-Timing**: Avoid cache-timing vulnerabilities in table lookups

### Parameter Selection Rationale

Parameters are chosen to ensure:

1. Security level meets or exceeds target (e.g., 128-bit classical security)
2. Decryption failure probability is negligible (< 2^-128)
3. Performance is practical for real-world applications
4. Ciphertext and key sizes are reasonable

---

## Performance Characteristics

### Approximate Timings

Performance on modern x86 CPU (single core, reference implementation):

| Operation | Kyber512 | Kyber768 | Kyber1024 | Dilithium2 | Dilithium3 | LightSaber | Saber | FireSaber |
|-----------|----------|----------|-----------|------------|------------|------------|-------|-----------|
| KeyGen | ~50us | ~80us | ~120us | ~60us | ~100us | ~45us | ~70us | ~95us |
| Encaps/Sign | ~65us | ~100us | ~140us | ~200us | ~350us | ~60us | ~90us | ~120us |
| Decaps/Verify | ~70us | ~110us | ~150us | ~80us | ~120us | ~65us | ~95us | ~125us |

*Note: These are estimates for optimized implementations. Python implementations will be significantly slower.*

### Size Comparison

Approximate sizes in bytes:

| Scheme | Public Key | Secret Key | Ciphertext/Signature |
|--------|------------|------------|---------------------|
| Kyber512 | 800 | 1632 | 768 |
| Kyber768 | 1184 | 2400 | 1088 |
| Kyber1024 | 1568 | 3168 | 1568 |
| Dilithium2 | 1312 | 2528 | 2420 |
| Dilithium3 | 1952 | 4000 | 3293 |
| LightSaber | 672 | 1568 | 736 |
| Saber | 992 | 2304 | 1088 |
| FireSaber | 1312 | 3040 | 1472 |

---

## Usage Examples

### Kyber KEM Example

```python
from pqcrypto.kyber_dilithium_saber import KyberKEM

# Initialize Kyber768 (Level 3 security)
kyber = KyberKEM('Kyber768')

# Generate keypair
public_key, secret_key = kyber.generate_keypair()

# Encapsulation (sender side)
shared_secret, ciphertext = kyber.encapsulate(public_key)
print(f"Shared secret: {shared_secret.hex()}")

# Decapsulation (receiver side)
recovered_secret = kyber.decapsulate(ciphertext, secret_key)
print(f"Recovered secret: {recovered_secret.hex()}")

assert shared_secret == recovered_secret
```

### Dilithium Signature Example

```python
from pqcrypto.kyber_dilithium_saber import DilithiumSignature

# Initialize Dilithium3 (Level 3 security)
dilithium = DilithiumSignature('Dilithium3')

# Generate signing keypair
public_key, secret_key = dilithium.generate_keypair()

# Sign a message
message = b"Important document to sign"
signature = dilithium.sign(message, secret_key)

# Verify signature
is_valid = dilithium.verify(message, signature, public_key)
print(f"Signature valid: {is_valid}")
```

### Saber KEM Example

```python
from pqcrypto.kyber_dilithium_saber import SaberKEM

# Initialize Saber (Level 3 security)
saber = SaberKEM('Saber')

# Generate keypair
public_key, secret_key = saber.generate_keypair()

# Encapsulation
shared_secret, ciphertext = saber.encapsulate(public_key)

# Decapsulation
recovered_secret = saber.decapsulate(ciphertext, secret_key)

assert shared_secret == recovered_secret
print("Key exchange successful!")
```

### Hybrid Cryptography Example

```python
from pqcrypto.kyber_dilithium_saber import KyberKEM, DilithiumSignature

# Initialize both KEM and signature scheme
kyber = KyberKEM('Kyber768')
dilithium = DilithiumSignature('Dilithium3')

# Generate keys
kem_pk, kem_sk = kyber.generate_keypair()
sig_pk, sig_sk = dilithium.generate_keypair()

# Sender: Encapsulate key and sign
shared_secret, ciphertext = kyber.encapsulate(kem_pk)
signature = dilithium.sign(str(ciphertext).encode(), sig_sk)

# Receiver: Verify signature and decapsulate
is_valid = dilithium.verify(str(ciphertext).encode(), signature, sig_pk)
if is_valid:
    recovered_secret = kyber.decapsulate(ciphertext, kem_sk)
    print("Authenticated key exchange successful!")
else:
    print("Signature verification failed!")
```

---

## References

1. **Kyber**: Bos, J., et al. "CRYSTALS-Kyber: A CCA-Secure Module-Lattice-Based KEM" (2018)
2. **Dilithium**: Ducas, L., et al. "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme" (2018)
3. **Saber**: D'Anvers, J.-P., et al. "SABER: Module-LWR based key exchange, CPA-secure encryption and CCA-secure KEM" (2018)
4. **NIST PQC**: https://csrc.nist.gov/projects/post-quantum-cryptography
5. **Lattice Cryptography**: Regev, O. "On lattices, learning with errors, random linear codes, and cryptography" (2005)

---

## Disclaimer

This is an **educational implementation** of post-quantum cryptographic algorithms. For production use:

1. ✅ Use officially standardized versions from NIST
2. ✅ Employ certified implementations (e.g., liboqs)
3. ✅ Conduct professional security audits
4. ✅ Implement constant-time operations
5. ✅ Consider side-channel protections
6. ✅ Follow security best practices

**DO NOT USE THIS EDUCATIONAL CODE IN PRODUCTION SYSTEMS**

For production deployments, use:
- **liboqs**: Open Quantum Safe library
- **PQClean**: Clean reference implementations
- **Vendor implementations**: From trusted cryptographic vendors

---

## Future Enhancements

Potential improvements for this implementation:

1. **Optimization**: NTT-based polynomial multiplication
2. **Serialization**: Efficient key and ciphertext encoding
3. **Batch Operations**: Process multiple operations efficiently
4. **Constant-Time**: Replace variable-time operations
5. **Hardware Acceleration**: Use AVX2/AVX-512 instructions
6. **Formal Verification**: Prove correctness properties

---

## Acknowledgments

This implementation is inspired by the work of the Kyber, Dilithium, and Saber teams, and the NIST Post-Quantum Cryptography Standardization project.
