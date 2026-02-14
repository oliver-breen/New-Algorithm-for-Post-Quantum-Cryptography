"""
HQC parameter sets (HQC-1, HQC-3, HQC-5).

Values are ported from the reference implementation in vendor/hqc.
"""

from dataclasses import dataclass
from typing import List, Dict


def ceil_divide(a: int, b: int) -> int:
    return (a // b) + (0 if a % b == 0 else 1)


def bitmask(a: int, size: int) -> int:
    return (1 << (a % size)) - 1


@dataclass(frozen=True)
class HQCParameters:
    name: str
    param_n: int
    param_n1: int
    param_n2: int
    param_n1n2: int
    param_omega: int
    param_omega_e: int
    param_omega_r: int
    param_security: int
    param_security_bytes: int
    param_dfr_exp: int
    param_delta: int
    param_m: int
    param_gf_poly: int
    param_gf_mul_order: int
    param_k: int
    param_g: int
    param_fft: int
    rs_poly_coefs: List[int]
    seed_bytes: int
    salt_bytes: int
    param_n_mu: int
    utils_rejection_threshold: int
    crypto_publickeybytes: int
    crypto_secretkeybytes: int
    crypto_ciphertextbytes: int
    crypto_bytes: int

    @property
    def vec_n_size_bytes(self) -> int:
        return ceil_divide(self.param_n, 8)

    @property
    def vec_k_size_bytes(self) -> int:
        return self.param_k

    @property
    def vec_k_size_64(self) -> int:
        return ceil_divide(self.param_k, 8)

    @property
    def vec_n1_size_bytes(self) -> int:
        return self.param_n1

    @property
    def vec_n1n2_size_bytes(self) -> int:
        return ceil_divide(self.param_n1n2, 8)

    @property
    def vec_n_size_64(self) -> int:
        return ceil_divide(self.param_n, 64)

    @property
    def vec_n1_size_64(self) -> int:
        return ceil_divide(self.param_n1, 8)

    @property
    def vec_n1n2_size_64(self) -> int:
        return ceil_divide(self.param_n1n2, 64)


HQC_1 = HQCParameters(
    name="HQC-1",
    param_n=17669,
    param_n1=46,
    param_n2=384,
    param_n1n2=17664,
    param_omega=66,
    param_omega_e=75,
    param_omega_r=75,
    param_security=128,
    param_security_bytes=16,
    param_dfr_exp=128,
    param_delta=15,
    param_m=8,
    param_gf_poly=0x11D,
    param_gf_mul_order=255,
    param_k=16,
    param_g=31,
    param_fft=4,
    rs_poly_coefs=[
        89, 69, 153, 116, 176, 117, 111, 75, 73, 233, 242, 233, 65, 210, 21, 139, 103,
        173, 67, 118, 105, 210, 174, 110, 74, 69, 228, 82, 255, 181, 1,
    ],
    seed_bytes=32,
    salt_bytes=16,
    param_n_mu=243079,
    utils_rejection_threshold=16767881,
    crypto_publickeybytes=2241,
    crypto_secretkeybytes=2321,
    crypto_ciphertextbytes=4433,
    crypto_bytes=32,
)

HQC_3 = HQCParameters(
    name="HQC-3",
    param_n=35851,
    param_n1=56,
    param_n2=640,
    param_n1n2=35840,
    param_omega=100,
    param_omega_e=114,
    param_omega_r=114,
    param_security=192,
    param_security_bytes=24,
    param_dfr_exp=192,
    param_delta=16,
    param_m=8,
    param_gf_poly=0x11D,
    param_gf_mul_order=255,
    param_k=24,
    param_g=33,
    param_fft=5,
    rs_poly_coefs=[
        45, 216, 239, 24, 253, 104, 27, 40, 107, 50, 163, 210, 227, 134, 224, 158,
        119, 13, 158, 1, 238, 164, 82, 43, 15, 232, 246, 142, 50, 189, 29, 232, 1,
    ],
    seed_bytes=32,
    salt_bytes=16,
    param_n_mu=119800,
    utils_rejection_threshold=16742417,
    crypto_publickeybytes=4514,
    crypto_secretkeybytes=4602,
    crypto_ciphertextbytes=8978,
    crypto_bytes=32,
)

HQC_5 = HQCParameters(
    name="HQC-5",
    param_n=57637,
    param_n1=90,
    param_n2=640,
    param_n1n2=57600,
    param_omega=131,
    param_omega_e=149,
    param_omega_r=149,
    param_security=256,
    param_security_bytes=32,
    param_dfr_exp=256,
    param_delta=29,
    param_m=8,
    param_gf_poly=0x11D,
    param_gf_mul_order=255,
    param_k=32,
    param_g=59,
    param_fft=5,
    rs_poly_coefs=[
        49, 167, 49, 39, 200, 121, 124, 91, 240, 63, 148, 71, 150, 123, 87, 101,
        32, 215, 159, 71, 201, 115, 97, 210, 186, 183, 141, 217, 123, 12, 31, 243,
        180, 219, 152, 239, 99, 141, 4, 246, 191, 144, 8, 232, 47, 27, 141, 178,
        130, 64, 124, 47, 39, 188, 216, 48, 199, 187, 1,
    ],
    seed_bytes=32,
    salt_bytes=16,
    param_n_mu=74517,
    utils_rejection_threshold=16772367,
    crypto_publickeybytes=7237,
    crypto_secretkeybytes=7333,
    crypto_ciphertextbytes=14421,
    crypto_bytes=32,
)


PARAMETER_SETS: Dict[str, HQCParameters] = {
    "HQC-1": HQC_1,
    "HQC-3": HQC_3,
    "HQC-5": HQC_5,
}


def get_parameters(name: str) -> HQCParameters:
    """Return the HQC parameter set by name (HQC-1, HQC-3, HQC-5)."""
    if name not in PARAMETER_SETS:
        raise ValueError(f"Unknown HQC parameter set: {name}")
    return PARAMETER_SETS[name]
