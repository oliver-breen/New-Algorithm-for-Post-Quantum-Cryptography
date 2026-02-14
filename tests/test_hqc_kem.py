"""
Tests for HQC KEM integration.
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from quantaweave import QuantaWeave


class TestHQCKEM(unittest.TestCase):
    """Test HQC KEM round-trip for all parameter sets."""

    def _round_trip(self, level: str):
        pqc = QuantaWeave(level)
        public_key, private_key = pqc.hqc_keypair()
        ciphertext, shared_secret = pqc.hqc_encapsulate(public_key)
        recovered_secret = pqc.hqc_decapsulate(ciphertext, private_key)
        self.assertEqual(shared_secret, recovered_secret)

    def test_hqc_1_round_trip(self):
        self._round_trip('LEVEL1')

    def test_hqc_3_round_trip(self):
        self._round_trip('LEVEL3')

    def test_hqc_5_round_trip(self):
        self._round_trip('LEVEL5')


if __name__ == '__main__':
    unittest.main()
