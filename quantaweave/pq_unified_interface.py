from abc import ABC, abstractmethod
from typing import Tuple, Any

class PQScheme(ABC):
    """
    Unified interface for post-quantum cryptographic schemes (KEM and Signature).
    Implementations should provide concrete methods for the supported operations.
    """

    @abstractmethod
    def generate_keypair(self) -> Tuple[Any, Any]:
        """
        Generate a public/secret key pair.
        Returns:
            (public_key, secret_key)
        """
        pass

    @abstractmethod
    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        """
        Encapsulate a shared secret using the public key (KEM).
        Returns:
            (ciphertext, shared_secret)
        """
        pass

    @abstractmethod
    def decapsulate(self, ciphertext: Any, secret_key: Any) -> Any:
        """
        Decapsulate the shared secret from the ciphertext using the secret key (KEM).
        Returns:
            shared_secret
        """
        pass

    @abstractmethod
    def sign(self, message: bytes, secret_key: Any) -> Any:
        """
        Sign a message using the secret key (Signature).
        Returns:
            signature
        """
        pass

    @abstractmethod
    def verify(self, message: bytes, signature: Any, public_key: Any) -> bool:
        """
        Verify a signature for a message using the public key (Signature).
        Returns:
            True if valid, False otherwise
        """
        pass
