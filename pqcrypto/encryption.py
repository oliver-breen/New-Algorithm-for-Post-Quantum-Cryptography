"""
Encryption and decryption for the post-quantum cryptography algorithm.

Implements LWE-based encryption scheme.
"""

from typing import Dict, List
import secrets
from .math_utils import (
    PolynomialRing, Sampler, 
    compress_poly, decompress_poly,
    compress, decompress
)


class Encryptor:
    """
    Encrypts messages using the public key.
    
    Uses LWE-based encryption with message encoding into polynomials.
    """
    
    def __init__(self, public_key: Dict):
        """
        Initialize encryptor with a public key.
        
        Args:
            public_key: Dictionary containing 'A', 'b', and 'params'
        """
        self.public_key = public_key
        self.params = public_key['params']
        self.n = self.params['n']
        self.q = self.params['q']
        self.eta = self.params['eta']
        self.du = self.params['du']
        self.dv = self.params['dv']
        self.ring = PolynomialRing(self.n, self.q)
    
    def encrypt(self, message: bytes) -> Dict:
        """
        Encrypt a message.
        
        Args:
            message: Bytes to encrypt (max length n // 8)
            
        Returns:
            Dictionary containing ciphertext components 'u' and 'v'
        """
        if len(message) > self.n // 8:
            raise ValueError(f"Message too long. Maximum {self.n // 8} bytes.")
        
        # Convert message to polynomial
        m = self._message_to_poly(message)
        
        # Sample random r, e1, e2
        r = Sampler.centered_binomial_sample(self.n, self.eta)
        e1 = Sampler.centered_binomial_sample(self.n, self.eta)
        e2 = Sampler.centered_binomial_sample(self.n, self.eta)
        
        # Extract A and b from public key
        A = self.public_key['A']
        b = self.public_key['b']
        
        # Compute u = Ar + e1
        Ar = self.ring.multiply_naive(A, r)
        u = self.ring.add(Ar, e1)
        
        # Compute v = br + e2 + encode(m)
        br = self.ring.multiply_naive(b, r)
        br_e2 = self.ring.add(br, e2)
        
        # Scale message to upper half of Z_q for better error tolerance
        m_scaled = self.ring.scalar_multiply(self.q // 2, m)
        v = self.ring.add(br_e2, m_scaled)
        
        # Compress u and v for smaller ciphertext
        u_compressed = compress_poly(u, self.q, self.du)
        v_compressed = compress_poly(v, self.q, self.dv)
        
        return {
            'u': u_compressed,
            'v': v_compressed,
            'params': self.params
        }
    
    def _message_to_poly(self, message: bytes) -> List[int]:
        """
        Convert a byte message to a binary polynomial.
        
        Each byte becomes 8 binary coefficients.
        """
        poly = []
        for byte in message:
            for i in range(8):
                bit = (byte >> i) & 1
                poly.append(bit)
        
        # Pad with zeros to reach dimension n
        while len(poly) < self.n:
            poly.append(0)
        
        return poly[:self.n]


class Decryptor:
    """
    Decrypts messages using the private key.
    """
    
    def __init__(self, private_key: Dict):
        """
        Initialize decryptor with a private key.
        
        Args:
            private_key: Dictionary containing 's' and 'params'
        """
        self.private_key = private_key
        self.params = private_key['params']
        self.n = self.params['n']
        self.q = self.params['q']
        self.du = self.params['du']
        self.dv = self.params['dv']
        self.ring = PolynomialRing(self.n, self.q)
    
    def decrypt(self, ciphertext: Dict) -> bytes:
        """
        Decrypt a ciphertext.
        
        Args:
            ciphertext: Dictionary containing 'u' and 'v'
            
        Returns:
            Decrypted message as bytes
        """
        # Decompress u and v
        u = decompress_poly(ciphertext['u'], self.q, self.du)
        v = decompress_poly(ciphertext['v'], self.q, self.dv)
        
        # Extract secret key
        s = self.private_key['s']
        
        # Compute m' = v - us
        us = self.ring.multiply_naive(u, s)
        m_noisy = self.ring.subtract(v, us)
        
        # Decode the message by rounding
        m_decoded = self._decode_message(m_noisy)
        
        # Convert polynomial back to bytes
        return self._poly_to_message(m_decoded)
    
    def _decode_message(self, poly: List[int]) -> List[int]:
        """
        Decode a noisy message polynomial to binary.
        
        Coefficients close to 0 decode to 0, close to q/2 decode to 1.
        """
        threshold = self.q // 4
        decoded = []
        
        for coef in poly:
            # Normalize to [0, q)
            coef = coef % self.q
            
            # Decide if closer to 0 or q/2
            if coef < threshold or coef > 3 * threshold:
                decoded.append(0)
            else:
                decoded.append(1)
        
        return decoded
    
    def _poly_to_message(self, poly: List[int]) -> bytes:
        """
        Convert a binary polynomial back to bytes.
        """
        message = []
        
        for i in range(0, len(poly), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(poly):
                    byte_val |= (poly[i + j] << j)
            message.append(byte_val)
        
        # Remove trailing zeros
        while message and message[-1] == 0:
            message.pop()
        
        return bytes(message)
