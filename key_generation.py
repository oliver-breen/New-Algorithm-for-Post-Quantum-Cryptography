"""
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Constants
default_key_size = 3072  # RSA key size in bits for post-quantum resistance

# Key Generation
def generate_key_pair(key_size=default_key_size):
    """
    Generate an RSA key pair for encryption/decryption purposes.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    return private_key, public_key


def save_key_to_file(key, filename, is_private=False):
    """
    Save a key (public or private) to a file.
    """
    encoding = serialization.Encoding.PEM
    if is_private:
        pem = key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        pem = key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    with open(filename, "wb") as key_file:
        key_file.write(pem)


if __name__ == "__main__":
    # Generate keys
    private_key, public_key = generate_key_pair()

    # Save them
    save_key_to_file(private_key, "private_key.pem", is_private=True)
    save_key_to_file(public_key, "public_key.pem")

    print("Keys are generated and saved as private_key.pem and public_key.pem")
"""