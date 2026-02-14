"""
Parsing and serialization helpers for HQC PKE/KEM.
"""

from typing import Dict, Tuple, List

from .parameters import HQCParameters
from .symmetric import xof_init
from .vector import vect_set_random, vect_sample_fixed_weight1
from .byte_utils import bytes_to_u64_list, u64_list_to_bytes


def hqc_dk_pke_from_string(params: HQCParameters, dk_pke: bytes) -> List[int]:
    xof = xof_init(dk_pke[: params.seed_bytes])
    return vect_sample_fixed_weight1(xof, params, params.param_omega)


def hqc_ek_pke_from_string(params: HQCParameters, ek_pke: bytes) -> Tuple[List[int], List[int]]:
    xof = xof_init(ek_pke[: params.seed_bytes])
    h = vect_set_random(xof, params)
    s_bytes = ek_pke[params.seed_bytes : params.seed_bytes + params.vec_n_size_bytes]
    s = bytes_to_u64_list(s_bytes, params.vec_n_size_64)
    return h, s


def hqc_c_kem_to_bytes(params: HQCParameters, c_pke: Dict[str, List[int]], salt: bytes) -> bytes:
    u_bytes = u64_list_to_bytes(c_pke["u"], params.vec_n_size_bytes)
    v_bytes = u64_list_to_bytes(c_pke["v"], params.vec_n1n2_size_bytes)
    return u_bytes + v_bytes + salt


def hqc_c_kem_from_bytes(params: HQCParameters, ct: bytes) -> Tuple[Dict[str, List[int]], bytes]:
    u = bytes_to_u64_list(ct[: params.vec_n_size_bytes], params.vec_n_size_64)
    v = bytes_to_u64_list(
        ct[params.vec_n_size_bytes : params.vec_n_size_bytes + params.vec_n1n2_size_bytes],
        params.vec_n1n2_size_64,
    )
    salt = ct[params.vec_n_size_bytes + params.vec_n1n2_size_bytes :]
    return {"u": u, "v": v}, salt
