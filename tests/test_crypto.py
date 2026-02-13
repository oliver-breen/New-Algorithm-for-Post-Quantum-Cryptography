"""
Unit tests for post-quantum cryptographic operations.

Tests for encapsulation and decapsulation in Kyber, Dilithium signatures,
and Saber KEM operations.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pqcrypto.kyber_dilithium_saber import KyberKEM, DilithiumSignature, SaberKEM


class TestKyberEncapsulation(unittest.TestCase):
    """Test Kyber key encapsulation mechanism."""
    
    def test_kyber512_encapsulate_decapsulate(self):
        """Test Kyber512 encapsulation and decapsulation."""
        kyber = KyberKEM('Kyber512')
        public_key, secret_key = kyber.generate_keypair()
        
        # Encapsulate
        shared_secret1, ciphertext = kyber.encapsulate(public_key)
        
        # Verify ciphertext structure
        self.assertIn('u', ciphertext)
        self.assertIn('v', ciphertext)
        self.assertIn('params', ciphertext)
        
        # Decapsulate
        shared_secret2 = kyber.decapsulate(ciphertext, secret_key)
        
        # Shared secrets should match
        self.assertEqual(shared_secret1, shared_secret2)
    
    def test_kyber768_encapsulate_decapsulate(self):
        """Test Kyber768 encapsulation and decapsulation."""
        kyber = KyberKEM('Kyber768')
        public_key, secret_key = kyber.generate_keypair()
        
        # Encapsulate
        shared_secret1, ciphertext = kyber.encapsulate(public_key)
        
        # Decapsulate
        shared_secret2 = kyber.decapsulate(ciphertext, secret_key)
        
        # Shared secrets should match
        self.assertEqual(shared_secret1, shared_secret2)
        self.assertEqual(len(shared_secret1), 32)  # 256 bits
    
    def test_kyber1024_encapsulate_decapsulate(self):
        """Test Kyber1024 encapsulation and decapsulation."""
        kyber = KyberKEM('Kyber1024')
        public_key, secret_key = kyber.generate_keypair()
        
        # Encapsulate
        shared_secret1, ciphertext = kyber.encapsulate(public_key)
        
        # Decapsulate
        shared_secret2 = kyber.decapsulate(ciphertext, secret_key)
        
        # Shared secrets should match
        self.assertEqual(shared_secret1, shared_secret2)
    
    def test_kyber_keypair_generation(self):
        """Test Kyber keypair generation has correct structure."""
        kyber = KyberKEM('Kyber768')
        public_key, secret_key = kyber.generate_keypair()
        
        # Check public key structure
        self.assertIn('A', public_key)
        self.assertIn('t', public_key)
        self.assertIn('params', public_key)
        
        # Check secret key structure
        self.assertIn('s', secret_key)
        self.assertIn('public_key', secret_key)
        self.assertIn('params', secret_key)
        
        # Check dimensions
        k = public_key['params']['k']
        self.assertEqual(len(public_key['A']), k)
        self.assertEqual(len(public_key['t']), k)
        self.assertEqual(len(secret_key['s']), k)
    
    def test_kyber_multiple_encapsulations(self):
        """Test multiple encapsulations produce different ciphertexts."""
        kyber = KyberKEM('Kyber768')
        public_key, secret_key = kyber.generate_keypair()
        
        # Encapsulate twice
        shared_secret1, ciphertext1 = kyber.encapsulate(public_key)
        shared_secret2, ciphertext2 = kyber.encapsulate(public_key)
        
        # Ciphertexts should differ (due to randomness)
        self.assertNotEqual(ciphertext1['u'], ciphertext2['u'])
        
        # Both should decapsulate correctly
        decap1 = kyber.decapsulate(ciphertext1, secret_key)
        decap2 = kyber.decapsulate(ciphertext2, secret_key)
        
        self.assertEqual(shared_secret1, decap1)
        self.assertEqual(shared_secret2, decap2)


class TestDilithiumSignature(unittest.TestCase):
    """Test Dilithium digital signature scheme."""
    
    def test_dilithium2_sign_verify(self):
        """Test Dilithium2 signing and verification."""
        dilithium = DilithiumSignature('Dilithium2')
        public_key, secret_key = dilithium.generate_keypair()
        
        # Sign message
        message = b"Hello, Post-Quantum World!"
        signature = dilithium.sign(message, secret_key)
        
        # Verify signature structure
        self.assertIn('z', signature)
        self.assertIn('c', signature)
        self.assertIn('params', signature)
        
        # Verify signature
        is_valid = dilithium.verify(message, signature, public_key)
        self.assertTrue(is_valid)
    
    def test_dilithium3_sign_verify(self):
        """Test Dilithium3 signing and verification."""
        dilithium = DilithiumSignature('Dilithium3')
        public_key, secret_key = dilithium.generate_keypair()
        
        # Sign message
        message = b"Quantum-resistant signatures"
        signature = dilithium.sign(message, secret_key)
        
        # Verify signature
        is_valid = dilithium.verify(message, signature, public_key)
        self.assertTrue(is_valid)
    
    def test_dilithium5_sign_verify(self):
        """Test Dilithium5 signing and verification."""
        dilithium = DilithiumSignature('Dilithium5')
        public_key, secret_key = dilithium.generate_keypair()
        
        # Sign message
        message = b"Maximum security level"
        signature = dilithium.sign(message, secret_key)
        
        # Verify signature
        is_valid = dilithium.verify(message, signature, public_key)
        self.assertTrue(is_valid)
    
    def test_dilithium_keypair_generation(self):
        """Test Dilithium keypair generation has correct structure."""
        dilithium = DilithiumSignature('Dilithium3')
        public_key, secret_key = dilithium.generate_keypair()
        
        # Check public key structure
        self.assertIn('A', public_key)
        self.assertIn('t', public_key)
        self.assertIn('params', public_key)
        
        # Check secret key structure
        self.assertIn('s1', secret_key)
        self.assertIn('s2', secret_key)
        self.assertIn('t', secret_key)
        self.assertIn('public_key', secret_key)
        
        # Check dimensions
        k = public_key['params']['k']
        l = public_key['params']['l']
        self.assertEqual(len(public_key['A']), k)
        self.assertEqual(len(public_key['t']), k)
        self.assertEqual(len(secret_key['s1']), l)
        self.assertEqual(len(secret_key['s2']), k)
    
    def test_dilithium_sign_different_messages(self):
        """Test signing different messages produces different signatures."""
        dilithium = DilithiumSignature('Dilithium3')
        public_key, secret_key = dilithium.generate_keypair()
        
        # Sign two different messages
        message1 = b"First message"
        message2 = b"Second message"
        
        signature1 = dilithium.sign(message1, secret_key)
        signature2 = dilithium.sign(message2, secret_key)
        
        # Signatures should differ
        self.assertNotEqual(signature1['z'], signature2['z'])
        
        # Both should verify correctly
        self.assertTrue(dilithium.verify(message1, signature1, public_key))
        self.assertTrue(dilithium.verify(message2, signature2, public_key))


class TestSaberEncapsulation(unittest.TestCase):
    """Test Saber key encapsulation mechanism."""
    
    def test_lightsaber_encapsulate_decapsulate(self):
        """Test LightSaber encapsulation and decapsulation."""
        saber = SaberKEM('LightSaber')
        public_key, secret_key = saber.generate_keypair()
        
        # Encapsulate
        shared_secret1, ciphertext = saber.encapsulate(public_key)
        
        # Verify ciphertext structure
        self.assertIn('c', ciphertext)
        self.assertIn('v', ciphertext)
        self.assertIn('params', ciphertext)
        
        # Decapsulate
        shared_secret2 = saber.decapsulate(ciphertext, secret_key)
        
        # Shared secrets should match
        self.assertEqual(shared_secret1, shared_secret2)
    
    def test_saber_encapsulate_decapsulate(self):
        """Test Saber encapsulation and decapsulation."""
        saber = SaberKEM('Saber')
        public_key, secret_key = saber.generate_keypair()
        
        # Encapsulate
        shared_secret1, ciphertext = saber.encapsulate(public_key)
        
        # Decapsulate
        shared_secret2 = saber.decapsulate(ciphertext, secret_key)
        
        # Shared secrets should match
        self.assertEqual(shared_secret1, shared_secret2)
        self.assertEqual(len(shared_secret1), 32)  # 256 bits
    
    def test_firesaber_encapsulate_decapsulate(self):
        """Test FireSaber encapsulation and decapsulation."""
        saber = SaberKEM('FireSaber')
        public_key, secret_key = saber.generate_keypair()
        
        # Encapsulate
        shared_secret1, ciphertext = saber.encapsulate(public_key)
        
        # Decapsulate
        shared_secret2 = saber.decapsulate(ciphertext, secret_key)
        
        # Shared secrets should match
        self.assertEqual(shared_secret1, shared_secret2)
    
    def test_saber_keypair_generation(self):
        """Test Saber keypair generation has correct structure."""
        saber = SaberKEM('Saber')
        public_key, secret_key = saber.generate_keypair()
        
        # Check public key structure
        self.assertIn('A', public_key)
        self.assertIn('b', public_key)
        self.assertIn('params', public_key)
        
        # Check secret key structure
        self.assertIn('s', secret_key)
        self.assertIn('public_key', secret_key)
        self.assertIn('params', secret_key)
        
        # Check dimensions
        l = public_key['params']['l']
        self.assertEqual(len(public_key['A']), l)
        self.assertEqual(len(public_key['b']), l)
        self.assertEqual(len(secret_key['s']), l)
    
    def test_saber_multiple_encapsulations(self):
        """Test multiple encapsulations produce different ciphertexts."""
        saber = SaberKEM('Saber')
        public_key, secret_key = saber.generate_keypair()
        
        # Encapsulate twice
        shared_secret1, ciphertext1 = saber.encapsulate(public_key)
        shared_secret2, ciphertext2 = saber.encapsulate(public_key)
        
        # Ciphertexts should differ (due to randomness)
        self.assertNotEqual(ciphertext1['c'], ciphertext2['c'])
        
        # Both should decapsulate correctly
        decap1 = saber.decapsulate(ciphertext1, secret_key)
        decap2 = saber.decapsulate(ciphertext2, secret_key)
        
        self.assertEqual(shared_secret1, decap1)
        self.assertEqual(shared_secret2, decap2)


class TestCrossAlgorithmComparison(unittest.TestCase):
    """Test comparisons between different algorithms."""
    
    def test_security_levels_consistent(self):
        """Test that security levels are correctly specified."""
        kyber512 = KyberKEM('Kyber512')
        lightsaber = SaberKEM('LightSaber')
        dilithium2 = DilithiumSignature('Dilithium2')
        
        # All should have 128-bit security
        self.assertEqual(kyber512.params['security_bits'], 128)
        self.assertEqual(lightsaber.params['security_bits'], 128)
        self.assertEqual(dilithium2.params['security_bits'], 128)
    
    def test_kyber_saber_comparison(self):
        """Test that both Kyber and Saber work correctly."""
        # Kyber
        kyber = KyberKEM('Kyber768')
        pk_kyber, sk_kyber = kyber.generate_keypair()
        ss1_kyber, ct_kyber = kyber.encapsulate(pk_kyber)
        ss2_kyber = kyber.decapsulate(ct_kyber, sk_kyber)
        self.assertEqual(ss1_kyber, ss2_kyber)
        
        # Saber
        saber = SaberKEM('Saber')
        pk_saber, sk_saber = saber.generate_keypair()
        ss1_saber, ct_saber = saber.encapsulate(pk_saber)
        ss2_saber = saber.decapsulate(ct_saber, sk_saber)
        self.assertEqual(ss1_saber, ss2_saber)
        
        # Both should produce 32-byte shared secrets
        self.assertEqual(len(ss1_kyber), 32)
        self.assertEqual(len(ss1_saber), 32)


if __name__ == '__main__':
    unittest.main()
