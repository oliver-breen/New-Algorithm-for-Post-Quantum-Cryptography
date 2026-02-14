"""
Security parameters for the QuantaWeave algorithm.

Based on lattice-based cryptography with configurable security levels.
"""

class SecurityParameters:
    """
    Defines security parameters for different security levels.
    
    Security levels:
    - LEVEL1: 128-bit quantum security (equivalent to AES-128)
    - LEVEL3: 192-bit quantum security (equivalent to AES-192)
    - LEVEL5: 256-bit quantum security (equivalent to AES-256)
    """
    
    LEVEL1 = {
        'n': 256,           # Polynomial dimension
        'q': 3329,          # Modulus (prime)
        'eta': 2,           # Noise parameter for secret key
        'du': 10,           # Compression parameter for u
        'dv': 4,            # Compression parameter for v
        'security_level': 128
    }
    
    LEVEL3 = {
        'n': 512,
        'q': 7681,
        'eta': 2,
        'du': 11,
        'dv': 5,
        'security_level': 192
    }
    
    LEVEL5 = {
        'n': 1024,
        'q': 12289,
        'eta': 2,
        'du': 11,
        'dv': 5,
        'security_level': 256
    }
    
    @staticmethod
    def get_parameters(level='LEVEL1'):
        """Get security parameters for a specific level."""
        params = {
            'LEVEL1': SecurityParameters.LEVEL1,
            'LEVEL3': SecurityParameters.LEVEL3,
            'LEVEL5': SecurityParameters.LEVEL5
        }
        return params.get(level, SecurityParameters.LEVEL1)
