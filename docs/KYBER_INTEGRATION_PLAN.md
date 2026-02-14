# Kyber Integration Plan

## Overview

This document describes a proposed integration of the NIST-standardized Kyber Key Encapsulation Mechanism (KEM) into the Post-Quantum Cryptography library.

## Current State

- **LWE Library**: Educational implementation in `quantaweave/` using the Learning With Errors problem
- **Status**: Placeholder functions exist in `kyber_dilithium_hqc.py` (no actual implementation)
- **Goal**: Add production-grade Kyber support alongside the educational LWE implementation

## Proposed Integration

### 1. Library Selection

**Recommended**: Use `liboqs-python` (from Open Quantum Safe)
- Maintained reference implementations
- NIST-standardized post-quantum algorithms
- Supports Kyber512, Kyber768, Kyber1024
- Better integration than pure Python ports

**Alternative**: `kyber-py` pure Python implementation
- Easier to audit
- No external dependencies
- Educational value
- Note: Version 1.2.0 has known API bugs (encaps/decaps return inconsistent byte lengths)

### 2. API Design

Add KEM methods to the `QuantaWeave` class in `quantaweave/core.py`:

```python
class QuantaWeave:
    def __init__(self, security_level='LEVEL1', use_kyber=False):
        """
        Initialize QuantaWeave with optional Kyber KEM support.
        
        Args:
            security_level: 'LEVEL1' (128-bit), 'LEVEL3' (192-bit), 'LEVEL5' (256-bit)
            use_kyber: If True, use Kyber KEM instead of LWE encryption
        """
        self.use_kyber = use_kyber
        if use_kyber:
            self._init_kyber()
        else:
            self.keygen = KeyGenerator(security_level)
    
    def _init_kyber(self):
        """Initialize Kyber KEM with appropriate variant."""
        # Map security levels to Kyber variants
        kyber_variants = {
            'LEVEL1': 'Kyber512',   # ~128-bit security
            'LEVEL3': 'Kyber768',   # ~192-bit security
            'LEVEL5': 'Kyber1024',  # ~256-bit security
        }
        self.kyber_variant = kyber_variants.get(self.security_level, 'Kyber1024')
    
    def kyber_keypair(self):
        """
        Generate a Kyber KEM keypair.
        
        Returns:
            Tuple of (encapsulation_key, decapsulation_key) as bytes
        """
        # Implementation using liboqs
        pass
    
    def kyber_encapsulate(self, encapsulation_key: bytes):
        """
        Encapsulate a shared secret with Kyber.
        
        Args:
            encapsulation_key: Public key bytes from kyber_keypair()
            
        Returns:
            Tuple of (ciphertext, shared_secret) as bytes
        """
        # Implementation using liboqs
        pass
    
    def kyber_decapsulate(self, ciphertext: bytes, decapsulation_key: bytes):
        """
        Decapsulate to recover the shared secret with Kyber.
        
        Args:
            ciphertext: Ciphertext from kyber_encapsulate()
            decapsulation_key: Private key from kyber_keypair()
            
        Returns:
            shared_secret as bytes
        """
        # Implementation using liboqs
        pass
```

### 3. Key Sizes and Performance

Expected key and ciphertext sizes for Kyber (NIST standard):

| Variant | Security | Encaps Key | Decaps Key | Ciphertext | Shared Secret |
|---------|----------|------------|------------|------------|---------------|
| Kyber512 | 128-bit | 800 bytes | 1,632 bytes | 768 bytes | 32 bytes |
| Kyber768 | 192-bit | 1,184 bytes | 2,400 bytes | 1,088 bytes | 32 bytes |
| Kyber1024 | 256-bit | 1,568 bytes | 3,168 bytes | 1,568 bytes | 32 bytes |

### 4. Usage Examples

```python
from quantaweave import QuantaWeave

# Using Kyber KEM instead of LWE
pqc = QuantaWeave(security_level='LEVEL5', use_kyber=True)

# Key generation
ek, dk = pqc.kyber_keypair()

# Alice encapsulates
ciphertext, shared_secret_alice = pqc.kyber_encapsulate(ek)

# Bob decapsulates
shared_secret_bob = pqc.kyber_decapsulate(ciphertext, dk)

# Verify
assert shared_secret_alice == shared_secret_bob
```

### 5. Implementation Steps

1. **Add liboqs dependency**
   - Update setup.py/requirements.txt
   - Document build requirements

2. **Create `quantaweave/kyber_kem.py`**
   - Wrapper around liboqs Kyber
   - Error handling
   - Type hints

3. **Extend `quantaweave/core.py`**
   - Add initialization parameter
   - Add kyber_keypair, kyber_encapsulate, kyber_decapsulate methods
   - Update docstrings

4. **Add tests in `tests/test_kyber.py`**
   - Test all three Kyber variants
   - Verify shared secret matching
   - Test edge cases

5. **Update documentation**
   - Add Kyber usage guide to `docs/ALGORITHM.md`
   - Add benchmarks to `examples/benchmark.py`
   - Update API reference

6. **Add example**
   - Create `examples/kyber_demo.py` showing Kyber usage
   - Comparison with LWE performance

### 6. Compatibility Considerations

**Backward Compatibility**:
- Default to LWE implementation (`use_kyber=False`)
- Existing API unchanged
- Kyber support is opt-in

**Side-by-side Usage**:
```python
# Can use both simultaneously
pqc_lwe = QuantaWeave(security_level='LEVEL1')  # Uses LWE
pqc_kyber = QuantaWeave(security_level='LEVEL1', use_kyber=True)  # Uses Kyber

# LWE: encryption/decryption of arbitrary messages
ct_lwe = pqc_lwe.encrypt(b"Hello", pk_lwe)
msg = pqc_lwe.decrypt(ct_lwe, sk_lwe)

# Kyber: KEM (key encapsulation for deriving shared secrets)
ek, dk = pqc_kyber.kyber_keypair()
ct_kyber, ss = pqc_kyber.kyber_encapsulate(ek)
ss_recv = pqc_kyber.kyber_decapsulate(ct_kyber, dk)
```

### 7. Security Considerations

- **NIST Standard**: Kyber is NIST-approved (ML-KEM)
- **Advantages**: Extensive cryptanalysis, reference implementations
- **Limitations**: KEM, not encryption (only for shared secret derivation)
- **Use Case**: Key agreement in hybrid protocols

### 8. Testing Strategy

```python
# From tests/test_kyber.py example
class TestKyberKEM(unittest.TestCase):
    def test_kyber512_roundtrip(self):
        pqc = QuantaWeave(security_level='LEVEL1', use_kyber=True)
        ek, dk = pqc.kyber_keypair()
        ct, ss1 = pqc.kyber_encapsulate(ek)
        ss2 = pqc.kyber_decapsulate(ct, dk)
        self.assertEqual(ss1, ss2)
    
    def test_kyber768_roundtrip(self):
        pqc = QuantaWeave(security_level='LEVEL3', use_kyber=True)
        ek, dk = pqc.kyber_keypair()
        ct, ss1 = pqc.kyber_encapsulate(ek)
        ss2 = pqc.kyber_decapsulate(ct, dk)
        self.assertEqual(ss1, ss2)
    
    def test_kyber1024_roundtrip(self):
        pqc = QuantaWeave(security_level='LEVEL5', use_kyber=True)
        ek, dk = pqc.kyber_keypair()
        ct, ss1 = pqc.kyber_encapsulate(ek)
        ss2 = pqc.kyber_decapsulate(ct, dk)
        self.assertEqual(ss1, ss2)
```

### 9. Documentation Updates

Update `docs/ALGORITHM.md` to include:
- Kyber algorithm overview
- Comparison of LWE vs Kyber
- When to use each approach
- Performance benchmarks
- Security guarantees

### 10. Timeline

1. **Phase 1** (Setup): Install liboqs, document API (1-2 hours)
2. **Phase 2** (Implementation): Create wrapper, integrate into QuantaWeave (2-3 hours)
3. **Phase 3** (Testing): Write comprehensive tests (1-2 hours)
4. **Phase 4** (Documentation): Update guides and examples (1-2 hours)

**Total Estimate**: 5-9 hours of development

## Alternative: Pure Python Kyber

If external dependencies are undesirable:
- Use `kyber-py` with bug fixes
- Pure Python, auditable
- Slower (~5-10x) than liboqs
- No build requirements

## Conclusion

Integrating Kyber adds production-grade PQC support while maintaining the educational LWE implementation. The proposed approach is backward-compatible and allows side-by-side usage of both algorithms.
