import importlib
from typing import Optional, Protocol, Tuple, cast


class _FalconBindings(Protocol):
    def keygen(self, n: int) -> Tuple[bytes, bytes]: ...

    def sign(self, n: int, secret_key: bytes, message: bytes) -> bytes: ...

    def verify(self, n: int, public_key: bytes, message: bytes, signature: bytes) -> bool: ...

    def sizes(self, n: int) -> Tuple[int, int, int]: ...


try:
    _falcon_module = importlib.import_module("quantaweave._falcon")
except Exception as exc:  # pragma: no cover - import-time guard
    _falcon_lib: Optional[_FalconBindings] = None
    _falcon_import_error: Optional[Exception] = exc
else:
    _falcon_lib = cast(_FalconBindings, _falcon_module)
    _falcon_import_error = None


class FalconSig:
    """
    Falcon signature wrapper.

    Args:
        parameter_set: "Falcon-512" or "Falcon-1024" (default).
    """

    def __init__(self, parameter_set: str = "Falcon-1024"):
        self._n = self._normalize_parameter_set(parameter_set)

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a Falcon public/secret keypair."""
        backend = self._require_backend()
        return backend.keygen(self._n)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign a message with a Falcon secret key."""
        backend = self._require_backend()
        skey = self._ensure_bytes(secret_key, "secret_key")
        msg = self._ensure_bytes(message, "message")
        return backend.sign(self._n, skey, msg)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a Falcon signature."""
        backend = self._require_backend()
        pkey = self._ensure_bytes(public_key, "public_key")
        msg = self._ensure_bytes(message, "message")
        sig = self._ensure_bytes(signature, "signature")
        return backend.verify(self._n, pkey, msg, sig)

    def sizes(self) -> Tuple[int, int, int]:
        """Return (public_key_len, secret_key_len, signature_len)."""
        backend = self._require_backend()
        return backend.sizes(self._n)

    @staticmethod
    def _ensure_bytes(value: bytes, label: str) -> bytes:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        raise TypeError(f"{label} must be bytes")

    @staticmethod
    def _normalize_parameter_set(parameter_set: str) -> int:
        if isinstance(parameter_set, int):
            if parameter_set in (512, 1024):
                return parameter_set
            raise ValueError("Unsupported Falcon parameter set")

        normalized = str(parameter_set).strip().upper().replace("_", "-")
        if normalized in ("FALCON-512", "512"):
            return 512
        if normalized in ("FALCON-1024", "1024"):
            return 1024
        raise ValueError("Unsupported Falcon parameter set")

    @staticmethod
    def _require_backend() -> _FalconBindings:
        if _falcon_lib is None:
            raise RuntimeError(
                "Falcon extension is not available. Build from source with GMP and pybind11."
            ) from _falcon_import_error
        return _falcon_lib
