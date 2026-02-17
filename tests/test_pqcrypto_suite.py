import unittest
from pqcrypto.pqcrypto_suite import PQCryptoSuite

class TestPQCryptoSuite(unittest.TestCase):
    def test_kem_keypair(self):
        suite = PQCryptoSuite(kem='kyber', sig='dilithium', level='LEVEL1')
        pk, sk = suite.kem_keypair()
        self.assertTrue('kyber' in pk.lower())
        self.assertTrue('kyber' in sk.lower())

    def test_kem_encapsulate_and_decapsulate(self):
        suite = PQCryptoSuite(kem='kyber', sig='dilithium', level='LEVEL1')
        pk, sk = suite.kem_keypair()
        ct, ss = suite.kem_encapsulate(pk)
        recovered = suite.kem_decapsulate(ct, sk)
        self.assertEqual(ss, recovered)

    def test_sig_keypair_and_sign_verify(self):
        suite = PQCryptoSuite(kem='kyber', sig='falcon', level='LEVEL1')
        pk, sk = suite.sig_keypair()
        msg = b"test message"
        sig = suite.sign(sk, msg)
        self.assertTrue(suite.verify(pk, msg, sig))
        self.assertFalse(suite.verify(pk, msg, "invalid_signature"))

if __name__ == '__main__':
    unittest.main()
