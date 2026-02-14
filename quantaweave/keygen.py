"""
Key generation for the QuantaWeave algorithm.

Implements key generation based on the Learning With Errors (LWE) problem.
"""

from typing import Tuple, Dict
from .parameters import SecurityParameters
from .math_utils import PolynomialRing, Sampler


class KeyGenerator:
    """
    Generates public and private key pairs for the QuantaWeave algorithm.
    
    Based on the LWE problem: given (A, b = As + e), it's hard to recover s.
    """
    
    def __init__(self, security_level: str = 'LEVEL1'):
        """
        Initialize key generator with security parameters.
        
        Args:
            security_level: Security level (LEVEL1, LEVEL3, or LEVEL5)
        """
        self.params = SecurityParameters.get_parameters(security_level)
        self.n = self.params['n']
        self.q = self.params['q']
        self.eta = self.params['eta']
        self.ring = PolynomialRing(self.n, self.q)
    
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """
        Generate a public/private key pair.
        
        Returns:
            Tuple of (public_key, private_key)
            - public_key: Dict with 'A' and 'b'
            - private_key: Dict with 's'
        """
        # Generate secret key s with small coefficients
        s = Sampler.centered_binomial_sample(self.n, self.eta)
        
        # Generate random public matrix A
        A = Sampler.uniform_sample(self.n, self.q)
        
        # Generate small error e
        e = Sampler.centered_binomial_sample(self.n, self.eta)
        
        # Compute b = As + e (mod q)
        As = self.ring.multiply_naive(A, s)
        b = self.ring.add(As, e)
        
        # Create public and private keys
        public_key = {
            'A': A,
            'b': b,
            'params': self.params
        }
        
        private_key = {
            's': s,
            'params': self.params
        }
        
        return public_key, private_key
    
    def get_security_level(self) -> int:
        """Return the security level in bits."""
        return self.params['security_level']
