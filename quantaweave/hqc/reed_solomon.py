"""
Reed-Solomon codec for HQC.

Ported from reed_solomon.c.
"""

from typing import List

from .parameters import HQCParameters
from .gf import gf_mul, gf_inverse, GF_EXP, GF_LOG
from .fft import fft, fft_retrieve_error_poly
from .byte_utils import bytes_to_u64_list, u64_list_to_bytes


def _alpha_ij_pow(params: HQCParameters) -> List[List[int]]:
    rows = 2 * params.param_delta
    cols = params.param_n1 - 1
    table = [[0 for _ in range(cols)] for _ in range(rows)]
    for i in range(rows):
        for j in range(1, params.param_n1):
            exp = ((i + 1) * j) % params.param_gf_mul_order
            table[i][j - 1] = GF_EXP[exp]
    return table


def compute_generator_poly(params: HQCParameters) -> List[int]:
    poly = [0] * (2 * params.param_delta + 1)
    poly[0] = 1
    tmp_degree = 0
    for i in range(1, 2 * params.param_delta + 1):
        for j in range(tmp_degree, 0, -1):
            poly[j] = GF_EXP[(GF_LOG[poly[j]] + i) % params.param_gf_mul_order] ^ poly[j - 1]
        poly[0] = GF_EXP[(GF_LOG[poly[0]] + i) % params.param_gf_mul_order]
        tmp_degree += 1
        poly[tmp_degree] = 1
    return poly


def reed_solomon_encode(params: HQCParameters, msg: List[int]) -> List[int]:
    msg_bytes = u64_list_to_bytes(msg, params.param_k)
    cdw_bytes = bytearray(params.param_n1)
    rs_poly = params.rs_poly_coefs

    for i in range(params.param_k):
        gate_value = msg_bytes[params.param_k - 1 - i] ^ cdw_bytes[params.param_n1 - params.param_k - 1]
        tmp = [gf_mul(gate_value, coef) for coef in rs_poly]
        for k in range(params.param_n1 - params.param_k - 1, 0, -1):
            cdw_bytes[k] = cdw_bytes[k - 1] ^ tmp[k]
        cdw_bytes[0] = tmp[0]

    cdw_bytes[params.param_n1 - params.param_k : params.param_n1] = msg_bytes
    return bytes_to_u64_list(bytes(cdw_bytes), params.vec_n1_size_64)


def _compute_syndromes(params: HQCParameters, cdw: bytes) -> List[int]:
    table = _alpha_ij_pow(params)
    syndromes = [0] * (2 * params.param_delta)
    for i in range(2 * params.param_delta):
        for j in range(1, params.param_n1):
            syndromes[i] ^= gf_mul(cdw[j], table[i][j - 1])
        syndromes[i] ^= cdw[0]
    return syndromes


def _compute_elp(params: HQCParameters, syndromes: List[int]) -> (List[int], int):
    sigma = [0] * (1 << params.param_fft)
    sigma[0] = 1
    deg_sigma = 0
    deg_sigma_p = 0
    deg_sigma_copy = 0
    sigma_copy = [0] * (params.param_delta + 1)
    x_sigma_p = [0] * (params.param_delta + 1)
    x_sigma_p[1] = 1
    pp = (1 << 16) - 1
    d_p = 1
    d = syndromes[0]

    for mu in range(2 * params.param_delta):
        sigma_copy[: params.param_delta] = sigma[: params.param_delta]
        deg_sigma_copy = deg_sigma

        dd = gf_mul(d, gf_inverse(d_p))
        for i in range(1, min(mu + 1, params.param_delta) + 1):
            sigma[i] ^= gf_mul(dd, x_sigma_p[i])

        deg_x = mu - pp
        deg_x_sigma_p = deg_x + deg_sigma_p

        mask1 = 0xFFFF if d != 0 else 0
        mask2 = 0xFFFF if deg_x_sigma_p > deg_sigma else 0
        mask12 = mask1 & mask2

        if mask12:
            deg_sigma = deg_x_sigma_p

        if mu == 2 * params.param_delta - 1:
            break

        if mask12:
            pp = mu
            d_p = d
            for i in range(params.param_delta, 0, -1):
                x_sigma_p[i] = sigma_copy[i - 1]
            deg_sigma_p = deg_sigma_copy
        else:
            for i in range(params.param_delta, 0, -1):
                x_sigma_p[i] = x_sigma_p[i - 1]

        d = syndromes[mu + 1]
        for i in range(1, min(mu + 1, params.param_delta) + 1):
            d ^= gf_mul(sigma[i], syndromes[mu + 1 - i])

    return sigma, deg_sigma


def _compute_z_poly(params: HQCParameters, sigma: List[int], degree: int, syndromes: List[int]) -> List[int]:
    z = [0] * (params.param_delta + 1)
    z[0] = 1
    for i in range(1, params.param_delta + 1):
        mask = 0xFFFF if i <= degree else 0
        z[i] = sigma[i] & mask
    z[1] ^= syndromes[0]
    for i in range(2, params.param_delta + 1):
        mask = 0xFFFF if i <= degree else 0
        z[i] ^= mask & syndromes[i - 1]
        for j in range(1, i):
            z[i] ^= mask & gf_mul(sigma[j], syndromes[i - j - 1])
    return z


def _compute_error_values(params: HQCParameters, z: List[int], error: List[int]) -> List[int]:
    beta_j = [0] * params.param_delta
    e_j = [0] * params.param_delta

    delta_counter = 0
    for i in range(params.param_n1):
        found = 0
        mask1 = 0xFFFF if error[i] != 0 else 0
        for j in range(params.param_delta):
            mask2 = 0xFFFF if j == delta_counter else 0
            beta_j[j] = (beta_j[j] + (mask1 & mask2 & GF_EXP[i])) & 0xFFFF
            found += 1 if (mask1 & mask2) else 0
        delta_counter += found
    delta_real_value = delta_counter

    for i in range(params.param_delta):
        tmp1 = 1
        tmp2 = 1
        inv = gf_inverse(beta_j[i])
        inv_power_j = 1
        for j in range(1, params.param_delta + 1):
            inv_power_j = gf_mul(inv_power_j, inv)
            tmp1 ^= gf_mul(inv_power_j, z[j])
        for k in range(1, params.param_delta):
            tmp2 = gf_mul(tmp2, (1 ^ gf_mul(inv, beta_j[(i + k) % params.param_delta])))
        mask1 = 0xFFFF if i < delta_real_value else 0
        e_j[i] = mask1 & gf_mul(tmp1, gf_inverse(tmp2))

    error_values = [0] * params.param_n1
    delta_counter = 0
    for i in range(params.param_n1):
        found = 0
        mask1 = 0xFFFF if error[i] != 0 else 0
        for j in range(params.param_delta):
            mask2 = 0xFFFF if j == delta_counter else 0
            error_values[i] += mask1 & mask2 & e_j[j]
            found += 1 if (mask1 & mask2) else 0
        delta_counter += found
    return error_values


def reed_solomon_decode(params: HQCParameters, cdw: List[int]) -> List[int]:
    cdw_bytes = bytearray(u64_list_to_bytes(cdw, params.param_n1))
    syndromes = _compute_syndromes(params, cdw_bytes)
    sigma, deg = _compute_elp(params, syndromes)
    error = fft_retrieve_error_poly(params, fft(params, sigma, params.param_delta + 1))
    z = _compute_z_poly(params, sigma, deg, syndromes)
    error_values = _compute_error_values(params, z, error)

    for i in range(params.param_n1):
        cdw_bytes[i] ^= error_values[i] & 0xFF

    msg_bytes = cdw_bytes[params.param_g - 1 : params.param_g - 1 + params.param_k]
    return bytes_to_u64_list(bytes(msg_bytes), params.vec_k_size_64)
