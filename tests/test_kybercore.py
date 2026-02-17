import unittest
from quantaweave.kyber import KyberCore
import os

class TestKyberCore(unittest.TestCase):
    def setUp(self):
        self.kyber = KyberCore()

    def test_keypair_and_encapsulation(self):
        pk, sk = self.kyber.keypair()
        self.assertIsInstance(pk, dict)
        self.assertIsInstance(sk, dict)
        ct, ss = self.kyber.encaps(pk)
        self.assertIsInstance(ct, dict)
        self.assertIsInstance(ss, bytes)
        recovered_ss = self.kyber.decaps(ct, sk)
        self.assertEqual(ss, recovered_ss)

    def test_encryption_and_decryption(self):
        pk, sk = self.kyber.keypair()
        message = os.urandom(32)
        coins = os.urandom(32)
        ct = self.kyber.encrypt(pk, message, coins)
        decrypted = self.kyber.decrypt(sk, ct)
        self.assertEqual(message, decrypted)

    def test_parameter_variants(self):
        for params in [
            {'k':2, 'eta1':3, 'eta2':2, 'du':10, 'dv':4}, # Kyber-512
            {'k':3, 'eta1':2, 'eta2':2, 'du':10, 'dv':4}, # Kyber-768
            {'k':4, 'eta1':2, 'eta2':2, 'du':11, 'dv':5}, # Kyber-1024
        ]:
            kyber = KyberCore(**params)
            pk, sk = kyber.keypair()
            ct, ss = kyber.encaps(pk)
            recovered_ss = kyber.decaps(ct, sk)
            self.assertEqual(ss, recovered_ss)

if __name__ == '__main__':
    unittest.main()
