"""
HQC symmetric primitives using SHA3/SHAKE.

This is a Python port of symmetric.c from the HQC reference code.
"""

from dataclasses import dataclass
from hashlib import sha3_256, sha3_512, shake_256
from typing import Optional, Protocol

from .parameters import HQCParameters

HQC_PRNG_DOMAIN = 0
HQC_XOF_DOMAIN = 1
HQC_G_FCT_DOMAIN = 0
HQC_H_FCT_DOMAIN = 1
HQC_I_FCT_DOMAIN = 2
HQC_J_FCT_DOMAIN = 3

class _ShakeLike(Protocol):
    """Protocol describing hashlib SHAKE objects."""

    def update(self, data: bytes) -> None:  # pragma: no cover - protocol definition
        ...

    def digest(self, length: int) -> bytes:  # pragma: no cover - protocol definition
        ...


@dataclass
class Shake256XOF:
    """Incremental SHAKE-256 XOF with domain separation."""

    _ctx: _ShakeLike
    _offset: int = 0

    @classmethod
    def from_seed(cls, seed: bytes, domain: int) -> "Shake256XOF":
        ctx = shake_256()
        ctx.update(seed)
        ctx.update(bytes([domain]))
        return cls(ctx, 0)

    def get_bytes(self, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        if size == 0:
            return b""
        end = self._offset + size
        data = self._ctx.digest(end)
        chunk = data[self._offset:end]
        self._offset = end
        return chunk


@dataclass
class Shake256PRNG:
    """SHAKE-256 based PRNG with domain separation."""

    _ctx: _ShakeLike
    _offset: int = 0

    @classmethod
    def init(cls, entropy_input: bytes, personalization: bytes) -> "Shake256PRNG":
        ctx = shake_256()
        ctx.update(entropy_input)
        ctx.update(personalization)
        ctx.update(bytes([HQC_PRNG_DOMAIN]))
        return cls(ctx, 0)

    def get_bytes(self, size: int) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        if size == 0:
            return b""
        end = self._offset + size
        data = self._ctx.digest(end)
        chunk = data[self._offset:end]
        self._offset = end
        return chunk


_PRNG: Optional["Shake256PRNG"] = None


def prng_init(entropy_input: bytes, personalization: bytes) -> None:
    """Initialize module-level PRNG context."""
    global _PRNG
    _PRNG = Shake256PRNG.init(entropy_input, personalization)


def prng_get_bytes(size: int) -> bytes:
    """Get bytes from module-level PRNG context."""
    if _PRNG is None:
        raise RuntimeError("PRNG not initialized; call prng_init() first")
    return _PRNG.get_bytes(size)


def xof_init(seed: bytes) -> Shake256XOF:
    """Initialize SHAKE-256 XOF with the HQC domain separator."""
    return Shake256XOF.from_seed(seed, HQC_XOF_DOMAIN)


def hash_i(params: HQCParameters, seed: bytes) -> bytes:
    """I: SHA3-512(seed) with domain separation, output 64 bytes."""
    if len(seed) != params.seed_bytes:
        raise ValueError("seed length mismatch")
    ctx = sha3_512()
    ctx.update(seed)
    ctx.update(bytes([HQC_I_FCT_DOMAIN]))
    return ctx.digest()


def hash_h(params: HQCParameters, ek_kem: bytes) -> bytes:
    """H: SHA3-256(ek_kem) with domain separation, output 32 bytes."""
    if len(ek_kem) != params.crypto_publickeybytes:
        raise ValueError("encapsulation key length mismatch")
    ctx = sha3_256()
    ctx.update(ek_kem)
    ctx.update(bytes([HQC_H_FCT_DOMAIN]))
    return ctx.digest()


def hash_g(params: HQCParameters, hash_ek_kem: bytes, m: bytes, salt: bytes) -> bytes:
    """G: SHA3-512(h_ek || m || salt) with domain separation, output 64 bytes."""
    if len(hash_ek_kem) != params.seed_bytes:
        raise ValueError("hash_ek_kem length mismatch")
    if len(m) != params.param_security_bytes:
        raise ValueError("message length mismatch")
    if len(salt) != params.salt_bytes:
        raise ValueError("salt length mismatch")
    ctx = sha3_512()
    ctx.update(hash_ek_kem)
    ctx.update(m)
    ctx.update(salt)
    ctx.update(bytes([HQC_G_FCT_DOMAIN]))
    return ctx.digest()


def hash_j(params: HQCParameters, hash_ek_kem: bytes, sigma: bytes, c_kem: bytes) -> bytes:
    """J: SHA3-256(h_ek || sigma || c_kem) with domain separation, output 32 bytes."""
    if len(hash_ek_kem) != params.seed_bytes:
        raise ValueError("hash_ek_kem length mismatch")
    if len(sigma) != params.param_security_bytes:
        raise ValueError("sigma length mismatch")
    if len(c_kem) != params.crypto_ciphertextbytes:
        raise ValueError("ciphertext length mismatch")
    ctx = sha3_256()
    ctx.update(hash_ek_kem)
    ctx.update(sigma)
    ctx.update(c_kem)
    ctx.update(bytes([HQC_J_FCT_DOMAIN]))
    return ctx.digest()
