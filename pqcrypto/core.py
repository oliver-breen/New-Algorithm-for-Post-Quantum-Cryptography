"""
Core API for the Post-Quantum Cryptography library.

Provides a simple interface for key generation, encryption, and decryption.
"""

from typing import Tuple, Dict
from .keygen import KeyGenerator
from .encryption import Encryptor, Decryptor


class PQCrypto:
    """
    Main interface for the Post-Quantum Cryptography system.
    
    Provides methods for:
    - Generating key pairs
    - Encrypting messages
    - Decrypting ciphertexts
    
    Example:
        >>> pqc = PQCrypto(security_level='LEVEL1')
        >>> public_key, private_key = pqc.generate_keypair()
        >>> ciphertext = pqc.encrypt(b"Hello, Quantum World!", public_key)
        >>> plaintext = pqc.decrypt(ciphertext, private_key)
        >>> print(plaintext)
        b'Hello, Quantum World!'
    """
    
    def __init__(self, security_level: str = 'LEVEL1'):
        """
        Initialize PQCrypto system.
        
        Args:
            security_level: Security level - 'LEVEL1' (128-bit), 
                          'LEVEL3' (192-bit), or 'LEVEL5' (256-bit)
        """
        self.security_level = security_level
        self.keygen = KeyGenerator(security_level)
    
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """
        Generate a new public/private key pair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        return self.keygen.generate_keypair()
    
    @staticmethod
    def encrypt(message: bytes, public_key: Dict) -> Dict:
        """
        Encrypt a message using a public key.
        
        Args:
            message: Message to encrypt (bytes)
            public_key: Public key dictionary
            
        Returns:
            Ciphertext dictionary
        """
        encryptor = Encryptor(public_key)
        return encryptor.encrypt(message)
    
    @staticmethod
    def decrypt(ciphertext: Dict, private_key: Dict) -> bytes:
        """
        Decrypt a ciphertext using a private key.
        
        Args:
            ciphertext: Ciphertext dictionary
            private_key: Private key dictionary
            
        Returns:
            Decrypted message (bytes)
        """
        decryptor = Decryptor(private_key)
        return decryptor.decrypt(ciphertext)
    
    def get_security_level(self) -> int:
        """
        Get the security level in bits.
        
        Returns:
            Security level (128, 192, or 256)
        """
        return self.keygen.get_security_level()
