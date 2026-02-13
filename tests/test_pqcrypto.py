"""
Tests for the Post-Quantum Cryptography library.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pqcrypto import PQCrypto
from pqcrypto.keygen import KeyGenerator
from pqcrypto.encryption import Encryptor, Decryptor
from pqcrypto.math_utils import PolynomialRing, Sampler
from pqcrypto.parameters import SecurityParameters


class TestMathUtils(unittest.TestCase):
    """Test mathematical utility functions."""
    
    def setUp(self):
        self.ring = PolynomialRing(n=256, q=3329)
    
    def test_polynomial_addition(self):
        """Test polynomial addition."""
        a = [1, 2, 3] + [0] * 253
        b = [4, 5, 6] + [0] * 253
        result = self.ring.add(a, b)
        self.assertEqual(result[0], 5)
        self.assertEqual(result[1], 7)
        self.assertEqual(result[2], 9)
    
    def test_polynomial_subtraction(self):
        """Test polynomial subtraction."""
        a = [10, 20, 30] + [0] * 253
        b = [5, 8, 12] + [0] * 253
        result = self.ring.subtract(a, b)
        self.assertEqual(result[0], 5)
        self.assertEqual(result[1], 12)
        self.assertEqual(result[2], 18)
    
    def test_polynomial_multiplication(self):
        """Test polynomial multiplication."""
        a = [1, 2] + [0] * 254
        b = [3, 4] + [0] * 254
        result = self.ring.multiply_naive(a, b)
        # (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2
        self.assertEqual(result[0], 3)
        self.assertEqual(result[1], 10)
        self.assertEqual(result[2], 8)
    
    def test_uniform_sampling(self):
        """Test uniform sampling."""
        sample = Sampler.uniform_sample(256, 3329)
        self.assertEqual(len(sample), 256)
        for val in sample:
            self.assertGreaterEqual(val, 0)
            self.assertLess(val, 3329)
    
    def test_centered_binomial_sampling(self):
        """Test centered binomial sampling."""
        sample = Sampler.centered_binomial_sample(256, 2)
        self.assertEqual(len(sample), 256)
        # Values should be small (typically in range [-4, 4] for eta=2)
        for val in sample:
            self.assertGreaterEqual(val, -4)
            self.assertLessEqual(val, 4)


class TestKeyGeneration(unittest.TestCase):
    """Test key generation."""
    
    def test_keypair_generation_level1(self):
        """Test key pair generation at security level 1."""
        keygen = KeyGenerator('LEVEL1')
        public_key, private_key = keygen.generate_keypair()
        
        # Check that keys have required components
        self.assertIn('A', public_key)
        self.assertIn('b', public_key)
        self.assertIn('params', public_key)
        self.assertIn('s', private_key)
        self.assertIn('params', private_key)
        
        # Check dimensions
        self.assertEqual(len(public_key['A']), 256)
        self.assertEqual(len(public_key['b']), 256)
        self.assertEqual(len(private_key['s']), 256)
    
    def test_keypair_generation_level3(self):
        """Test key pair generation at security level 3."""
        keygen = KeyGenerator('LEVEL3')
        public_key, private_key = keygen.generate_keypair()
        
        self.assertEqual(len(public_key['A']), 512)
        self.assertEqual(len(public_key['b']), 512)
    
    def test_security_level(self):
        """Test security level retrieval."""
        keygen = KeyGenerator('LEVEL1')
        self.assertEqual(keygen.get_security_level(), 128)
        
        keygen = KeyGenerator('LEVEL5')
        self.assertEqual(keygen.get_security_level(), 256)


class TestEncryptionDecryption(unittest.TestCase):
    """Test encryption and decryption."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.keygen = KeyGenerator('LEVEL1')
        self.public_key, self.private_key = self.keygen.generate_keypair()
    
    def test_encrypt_decrypt_short_message(self):
        """Test encryption and decryption of a short message."""
        message = b"Hello"
        
        encryptor = Encryptor(self.public_key)
        ciphertext = encryptor.encrypt(message)
        
        decryptor = Decryptor(self.private_key)
        decrypted = decryptor.decrypt(ciphertext)
        
        self.assertEqual(message, decrypted)
    
    def test_encrypt_decrypt_long_message(self):
        """Test encryption and decryption of a longer message."""
        message = b"This is a longer test message!"
        
        encryptor = Encryptor(self.public_key)
        ciphertext = encryptor.encrypt(message)
        
        decryptor = Decryptor(self.private_key)
        decrypted = decryptor.decrypt(ciphertext)
        
        self.assertEqual(message, decrypted)
    
    def test_encrypt_decrypt_binary_data(self):
        """Test encryption of binary data."""
        message = bytes(range(20))  # Binary data
        
        encryptor = Encryptor(self.public_key)
        ciphertext = encryptor.encrypt(message)
        
        decryptor = Decryptor(self.private_key)
        decrypted = decryptor.decrypt(ciphertext)
        
        self.assertEqual(message, decrypted)
    
    def test_ciphertext_structure(self):
        """Test that ciphertext has correct structure."""
        message = b"Test"
        
        encryptor = Encryptor(self.public_key)
        ciphertext = encryptor.encrypt(message)
        
        self.assertIn('u', ciphertext)
        self.assertIn('v', ciphertext)
        self.assertIn('params', ciphertext)
    
    def test_message_too_long(self):
        """Test that overly long messages raise an error."""
        message = b"x" * 100  # Too long for n=256
        
        encryptor = Encryptor(self.public_key)
        with self.assertRaises(ValueError):
            encryptor.encrypt(message)


class TestPQCryptoAPI(unittest.TestCase):
    """Test the main PQCrypto API."""
    
    def test_full_workflow(self):
        """Test complete encryption workflow."""
        pqc = PQCrypto('LEVEL1')
        
        # Generate keys
        public_key, private_key = pqc.generate_keypair()
        
        # Encrypt message
        message = b"Quantum-safe encryption!"
        ciphertext = pqc.encrypt(message, public_key)
        
        # Decrypt message
        decrypted = pqc.decrypt(ciphertext, private_key)
        
        self.assertEqual(message, decrypted)
    
    def test_different_security_levels(self):
        """Test encryption at different security levels."""
        for level in ['LEVEL1', 'LEVEL3', 'LEVEL5']:
            pqc = PQCrypto(level)
            public_key, private_key = pqc.generate_keypair()
            
            message = b"Test message"
            ciphertext = pqc.encrypt(message, public_key)
            decrypted = pqc.decrypt(ciphertext, private_key)
            
            self.assertEqual(message, decrypted)
    
    def test_multiple_encryptions(self):
        """Test that multiple encryptions produce different ciphertexts."""
        pqc = PQCrypto('LEVEL1')
        public_key, private_key = pqc.generate_keypair()
        
        message = b"Same message"
        ciphertext1 = pqc.encrypt(message, public_key)
        ciphertext2 = pqc.encrypt(message, public_key)
        
        # Due to randomness, ciphertexts should differ
        self.assertNotEqual(ciphertext1['u'], ciphertext2['u'])
        
        # But both should decrypt correctly
        self.assertEqual(pqc.decrypt(ciphertext1, private_key), message)
        self.assertEqual(pqc.decrypt(ciphertext2, private_key), message)


class TestSecurityParameters(unittest.TestCase):
    """Test security parameters."""
    
    def test_parameter_retrieval(self):
        """Test retrieving security parameters."""
        params1 = SecurityParameters.get_parameters('LEVEL1')
        self.assertEqual(params1['n'], 256)
        self.assertEqual(params1['security_level'], 128)
        
        params3 = SecurityParameters.get_parameters('LEVEL3')
        self.assertEqual(params3['n'], 512)
        self.assertEqual(params3['security_level'], 192)
    
    def test_default_parameters(self):
        """Test default parameter retrieval."""
        params = SecurityParameters.get_parameters()
        self.assertEqual(params['security_level'], 128)


if __name__ == '__main__':
    unittest.main()
