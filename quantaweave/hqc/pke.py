"""
HQC public-key encryption (PKE) layer.

Ported from hqc.c.
"""

from typing import Dict, Tuple

from .parameters import HQCParameters
from .symmetric import hash_i, xof_init
from .vector import (
    vect_sample_fixed_weight1,
    vect_sample_fixed_weight2,
    vect_set_random,
    vect_add,
    vect_truncate,
)
from .gf2x import vect_mul
from .parsing import hqc_ek_pke_from_string, hqc_dk_pke_from_string
from .code import code_encode, code_decode
from .byte_utils import bytes_to_u64_list, u64_list_to_bytes


def hqc_pke_keygen(params: HQCParameters, seed: bytes) -> Tuple[bytes, bytes]:
    keypair_seed = hash_i(params, seed)
    seed_dk = keypair_seed[: params.seed_bytes]
    seed_ek = keypair_seed[params.seed_bytes : 2 * params.seed_bytes]

    dk_xof = xof_init(seed_dk)
    y = vect_sample_fixed_weight1(dk_xof, params, params.param_omega)
    x = vect_sample_fixed_weight1(dk_xof, params, params.param_omega)

    ek_xof = xof_init(seed_ek)
    h = vect_set_random(ek_xof, params)
    s = vect_mul(params, y, h)
    s = vect_add(x, s)

    ek_pke = seed_ek + u64_list_to_bytes(s, params.vec_n_size_bytes)
    dk_pke = seed_dk
    return ek_pke, dk_pke


def hqc_pke_encrypt(params: HQCParameters, ek_pke: bytes, message: bytes, theta: bytes) -> Dict[str, list]:
    theta_xof = xof_init(theta)
    h, s = hqc_ek_pke_from_string(params, ek_pke)

    r2 = vect_sample_fixed_weight2(theta_xof, params, params.param_omega_r)
    e = vect_sample_fixed_weight2(theta_xof, params, params.param_omega_e)
    r1 = vect_sample_fixed_weight2(theta_xof, params, params.param_omega_r)

    u = vect_add(r1, vect_mul(params, r2, h))

    m_vec = bytes_to_u64_list(message, params.vec_k_size_64)
    v = code_encode(params, m_vec)

    tmp = vect_mul(params, r2, s)
    tmp = vect_add(tmp, e)
    tmp = vect_truncate(params, tmp)
    v = vect_add(v, tmp)

    return {"u": u, "v": v}


def hqc_pke_decrypt(params: HQCParameters, dk_pke: bytes, c_pke: Dict[str, list]) -> bytes:
    y = hqc_dk_pke_from_string(params, dk_pke)
    tmp1 = vect_mul(params, y, c_pke["u"])
    tmp1 = vect_truncate(params, tmp1)
    tmp2 = vect_add(c_pke["v"], tmp1)
    m_vec = code_decode(params, tmp2)
    return u64_list_to_bytes(m_vec, params.param_k)
