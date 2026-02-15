import hashlib
import os
from typing import Tuple

def keygen(n: int) -> Tuple[bytes, bytes]:
    # Mock keygen with random bytes
    if n == 512:
        return os.urandom(897), os.urandom(1281)
    elif n == 1024:
        return os.urandom(1793), os.urandom(2305)
    raise ValueError("Invalid n")

def sign(n: int, secret_key: bytes, message: bytes) -> bytes:
    # Mock sign with random bytes + hash prefix
    h = hashlib.sha256(message).digest()
    if n == 512:
        sig_len = 666
    elif n == 1024:
        sig_len = 1280
    else:
        raise ValueError("Invalid n")
    
    padding = os.urandom(sig_len - len(h))
    return h + padding

def verify(n: int, public_key: bytes, message: bytes, signature: bytes) -> bool:
    # Mock verify
    h = hashlib.sha256(message).digest()
    
    # Check lengths
    if n == 512:
        if len(public_key) != 897 or len(signature) != 666:
            return False
    elif n == 1024:
        if len(public_key) != 1793 or len(signature) != 1280:
            return False
            
    # Check content
    return signature.startswith(h)

def sizes(n: int) -> Tuple[int, int, int]:
    # Mock sizes
    if n == 512:
        return 897, 1281, 666
    elif n == 1024:
        return 1793, 2305, 1280
    raise ValueError("Invalid n")
