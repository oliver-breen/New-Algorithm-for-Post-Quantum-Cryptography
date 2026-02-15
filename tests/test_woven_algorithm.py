import unittest
from quantaweave.woven_algorithm import QuantaWeaveAlgorithm

class TestQuantaWeaveAlgorithm(unittest.TestCase):
    """
    Test suite for the Woven Algorithm (Kyber + HQC + Dilithium).
    """

    def setUp(self):
        self.algo = QuantaWeaveAlgorithm()

    def test_keypair_generation(self):
        """Test generation of serialized keys."""
        pk, sk = self.algo.generate_keypair()
        self.assertIsInstance(pk, bytes)
        self.assertIsInstance(sk, bytes)
        self.assertGreater(len(pk), 0)
        self.assertGreater(len(sk), 0)

    def test_encapsulation_decapsulation(self):
        """Test hybrid KEM functionality (Kyber + HQC)."""
        pk, sk = self.algo.generate_keypair()
        ct, ss = self.algo.encapsulate(pk)
        
        self.assertIsInstance(ct, bytes)
        self.assertIsInstance(ss, bytes)
        self.assertEqual(len(ss), 32, "Shared secret should be 32 bytes (default combiner)")
        
        ss_recovered = self.algo.decapsulate(ct, sk)
        self.assertEqual(ss, ss_recovered, "Decapsulation failed")

    def test_signature(self):
        """Test hybrid signature functionality (Dilithium)."""
        pk, sk = self.algo.generate_keypair()
        message = b"Test message for woven signature"
        
        sig = self.algo.sign(message, sk)
        self.assertIsInstance(sig, bytes)
        self.assertGreater(len(sig), 0)
        
        valid = self.algo.verify(message, sig, pk)
        self.assertTrue(valid, "Signature verification failed")
        
        invalid = self.algo.verify(b"Tampered message", sig, pk)
        self.assertFalse(invalid, "Signature verification should fail for tampered message")

if __name__ == '__main__':
    unittest.main()
