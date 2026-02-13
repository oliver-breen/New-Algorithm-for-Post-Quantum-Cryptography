"""
Mathematical utilities for polynomial operations in lattice-based cryptography.

Implements polynomial arithmetic, sampling, and NTT (Number Theoretic Transform).
"""

import secrets
from typing import List


class PolynomialRing:
    """
    Represents a polynomial ring R_q = Z_q[X]/(X^n + 1).
    
    Operations are performed modulo q and modulo (X^n + 1).
    """
    
    def __init__(self, n: int, q: int):
        """
        Initialize polynomial ring.
        
        Args:
            n: Degree of the polynomial (dimension)
            q: Modulus
        """
        self.n = n
        self.q = q
    
    def add(self, a: List[int], b: List[int]) -> List[int]:
        """Add two polynomials in the ring."""
        result = [(a[i] + b[i]) % self.q for i in range(self.n)]
        return result
    
    def subtract(self, a: List[int], b: List[int]) -> List[int]:
        """Subtract two polynomials in the ring."""
        result = [(a[i] - b[i]) % self.q for i in range(self.n)]
        return result
    
    def multiply_naive(self, a: List[int], b: List[int]) -> List[int]:
        """
        Multiply two polynomials using naive O(n^2) algorithm.
        
        Performs multiplication in Z_q[X]/(X^n + 1).
        """
        result = [0] * self.n
        
        for i in range(self.n):
            for j in range(self.n):
                # Multiply coefficients
                prod = (a[i] * b[j]) % self.q
                
                # Add to appropriate position, handling X^n = -1
                if i + j < self.n:
                    result[i + j] = (result[i + j] + prod) % self.q
                else:
                    # When power >= n, use X^n = -1
                    result[i + j - self.n] = (result[i + j - self.n] - prod) % self.q
        
        return result
    
    def scalar_multiply(self, scalar: int, poly: List[int]) -> List[int]:
        """Multiply a polynomial by a scalar."""
        return [(scalar * coef) % self.q for coef in poly]
    
    def negate(self, poly: List[int]) -> List[int]:
        """Negate a polynomial."""
        return [(-coef) % self.q for coef in poly]


class Sampler:
    """Sampling functions for generating polynomials with specific distributions."""
    
    @staticmethod
    def uniform_sample(n: int, q: int) -> List[int]:
        """
        Sample a polynomial uniformly from Z_q.
        
        Args:
            n: Polynomial dimension
            q: Modulus
            
        Returns:
            List of n coefficients sampled uniformly from [0, q)
        """
        return [secrets.randbelow(q) for _ in range(n)]
    
    @staticmethod
    def centered_binomial_sample(n: int, eta: int) -> List[int]:
        """
        Sample from centered binomial distribution.
        
        This generates small errors by sampling from a distribution centered at 0.
        Each coefficient is sampled as the difference of two binomial samples.
        
        Args:
            n: Polynomial dimension
            eta: Parameter controlling distribution width
            
        Returns:
            List of n coefficients from centered binomial distribution
        """
        result = []
        for _ in range(n):
            # Sample two binomial random variables
            a = sum(secrets.randbelow(2) for _ in range(eta))
            b = sum(secrets.randbelow(2) for _ in range(eta))
            result.append(a - b)
        return result
    
    @staticmethod
    def ternary_sample(n: int) -> List[int]:
        """
        Sample a ternary polynomial with coefficients in {-1, 0, 1}.
        
        Args:
            n: Polynomial dimension
            
        Returns:
            List of n coefficients from {-1, 0, 1}
        """
        return [secrets.randbelow(3) - 1 for _ in range(n)]


def compress(value: int, q: int, d: int) -> int:
    """
    Compress a value from Z_q to a smaller range.
    
    Args:
        value: Value to compress (0 <= value < q)
        q: Original modulus
        d: Number of bits in compressed representation
        
    Returns:
        Compressed value
    """
    return (value * (2 ** d) // q) % (2 ** d)


def decompress(value: int, q: int, d: int) -> int:
    """
    Decompress a value back to Z_q.
    
    Args:
        value: Compressed value
        q: Target modulus
        d: Number of bits in compressed representation
        
    Returns:
        Decompressed value
    """
    return (value * q) // (2 ** d)


def compress_poly(poly: List[int], q: int, d: int) -> List[int]:
    """Compress all coefficients of a polynomial."""
    return [compress(coef, q, d) for coef in poly]


def decompress_poly(poly: List[int], q: int, d: int) -> List[int]:
    """Decompress all coefficients of a polynomial."""
    return [decompress(coef, q, d) for coef in poly]
