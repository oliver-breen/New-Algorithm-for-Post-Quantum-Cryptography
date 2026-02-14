import unittest

from quantaweave import FalconSig


def _falcon_available() -> bool:
    try:
        FalconSig().sizes()
    except RuntimeError:
        return False
    return True


@unittest.skipUnless(_falcon_available(), "Falcon backend unavailable")
class TestFalconSig(unittest.TestCase):
    def test_sign_verify_round_trip(self) -> None:
        falcon = FalconSig("Falcon-1024")
        pkey, skey = falcon.keygen()
        msg = b"falcon signature test"

        sig = falcon.sign(skey, msg)
        self.assertTrue(falcon.verify(pkey, msg, sig))
        self.assertFalse(falcon.verify(pkey, msg + b"!", sig))

    def test_sizes_match_material(self) -> None:
        falcon = FalconSig("Falcon-1024")
        pk_len, sk_len, sig_len = falcon.sizes()
        pkey, skey = falcon.keygen()
        msg = b"size check"
        sig = falcon.sign(skey, msg)

        self.assertEqual(len(pkey), pk_len)
        self.assertEqual(len(skey), sk_len)
        self.assertEqual(len(sig), sig_len)


if __name__ == "__main__":
    unittest.main()
