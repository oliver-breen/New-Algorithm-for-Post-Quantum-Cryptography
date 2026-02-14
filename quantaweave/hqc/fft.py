"""
Additive FFT helpers for HQC Reed-Solomon decoding.

Ported from fft.c in the HQC reference implementation.
"""

from typing import List, Tuple

from .parameters import HQCParameters
from .gf import gf_mul, gf_square, gf_inverse, GF_LOG


def _compute_fft_betas(params: HQCParameters) -> List[int]:
    return [1 << (params.param_m - 1 - i) for i in range(params.param_m - 1)]


def _compute_subset_sums(set_vals: List[int]) -> List[int]:
    subset_sums = [0] * (1 << len(set_vals))
    for i, val in enumerate(set_vals):
        for j in range(1 << i):
            subset_sums[(1 << i) + j] = val ^ subset_sums[j]
    return subset_sums


def _radix(f: List[int], m_f: int) -> Tuple[List[int], List[int]]:
    half = 1 << (m_f - 1)
    f0 = [0] * half
    f1 = [0] * half

    if m_f == 4:
        f0[4] = f[8] ^ f[12]
        f0[6] = f[12] ^ f[14]
        f0[7] = f[14] ^ f[15]
        f1[5] = f[11] ^ f[13]
        f1[6] = f[13] ^ f[14]
        f1[7] = f[15]
        f0[5] = f[10] ^ f[12] ^ f1[5]
        f1[4] = f[9] ^ f[13] ^ f0[5]

        f0[0] = f[0]
        f1[3] = f[7] ^ f[11] ^ f[15]
        f0[3] = f[6] ^ f[10] ^ f[14] ^ f1[3]
        f0[2] = f[4] ^ f0[4] ^ f0[3] ^ f1[3]
        f1[1] = f[3] ^ f[5] ^ f[9] ^ f[13] ^ f1[3]
        f1[2] = f[3] ^ f1[1] ^ f0[3]
        f0[1] = f[2] ^ f0[2] ^ f1[1]
        f1[0] = f[1] ^ f0[1]
    elif m_f == 3:
        f0[0] = f[0]
        f0[2] = f[4] ^ f[6]
        f0[3] = f[6] ^ f[7]
        f1[1] = f[3] ^ f[5] ^ f[7]
        f1[2] = f[5] ^ f[6]
        f1[3] = f[7]
        f0[1] = f[2] ^ f0[2] ^ f1[1]
        f1[0] = f[1] ^ f0[1]
    elif m_f == 2:
        f0[0] = f[0]
        f0[1] = f[2] ^ f[3]
        f1[0] = f[1] ^ f0[1]
        f1[1] = f[3]
    elif m_f == 1:
        f0[0] = f[0]
        f1[0] = f[1]
    else:
        f0, f1 = _radix_big(f, m_f)

    return f0, f1


def _radix_big(f: List[int], m_f: int) -> Tuple[List[int], List[int]]:
    n = 1 << (m_f - 2)
    q = [0] * (2 * n + 1)
    r = [0] * (2 * n + 1)

    q0 = [0] * (1 << (m_f - 2))
    q1 = [0] * (1 << (m_f - 2))
    r0 = [0] * (1 << (m_f - 2))
    r1 = [0] * (1 << (m_f - 2))

    q[:2 * n] = f[3 * n : 3 * n + 2 * n]
    q[n : n + 2 * n] = f[3 * n : 3 * n + 2 * n]
    r[:4 * n] = f[:4 * n]

    for i in range(n):
        q[i] ^= f[2 * n + i]
        r[n + i] ^= q[i]

    q0, q1 = _radix(q, m_f - 1)
    r0, r1 = _radix(r, m_f - 1)

    f0 = [0] * (1 << (m_f - 1))
    f1 = [0] * (1 << (m_f - 1))
    f0[:2 * n] = r0[:2 * n]
    f0[n : n + 2 * n] = q0[:2 * n]
    f1[:2 * n] = r1[:2 * n]
    f1[n : n + 2 * n] = q1[:2 * n]

    return f0, f1


def _fft_rec(params: HQCParameters, f: List[int], f_coeffs: int, m: int, m_f: int, betas: List[int]) -> List[int]:
    if m_f == 1:
        w = [0] * (1 << m)
        tmp = [0] * m
        for i in range(m):
            tmp[i] = gf_mul(betas[i], f[1])

        w[0] = f[0]
        x = 1
        for j in range(m):
            for k in range(x):
                w[x + k] = w[k] ^ tmp[j]
            x <<= 1
        return w

    f0, f1 = _radix(f, m_f)

    if betas[m - 1] != 1:
        beta_m_pow = 1
        x = 1 << m_f
        for i in range(1, x):
            beta_m_pow = gf_mul(beta_m_pow, betas[m - 1])
            f[i] = gf_mul(beta_m_pow, f[i])

    gammas = [0] * (m - 1)
    deltas = [0] * (m - 1)
    for i in range(m - 1):
        gammas[i] = gf_mul(betas[i], gf_inverse(betas[m - 1]))
        deltas[i] = gf_square(gammas[i]) ^ gammas[i]

    gammas_sums = _compute_subset_sums(gammas)

    u = _fft_rec(params, f0, (f_coeffs + 1) // 2, m - 1, m_f - 1, deltas)
    k = 1 << (m - 1)

    if f_coeffs <= 3:
        w = [0] * (2 * k)
        w[0] = u[0]
        w[k] = u[0] ^ f1[0]
        for i in range(1, k):
            w[i] = u[i] ^ gf_mul(gammas_sums[i], f1[0])
            w[k + i] = w[i] ^ f1[0]
        return w

    v = _fft_rec(params, f1, f_coeffs // 2, m - 1, m_f - 1, deltas)
    w = [0] * (2 * k)
    w[k:] = v[:2 * k]
    w[0] = u[0]
    w[k] ^= u[0]
    for i in range(1, k):
        w[i] = u[i] ^ gf_mul(gammas_sums[i], v[i])
        w[k + i] ^= w[i]
    return w


def fft(params: HQCParameters, f: List[int], f_coeffs: int) -> List[int]:
    betas = _compute_fft_betas(params)
    betas_sums = _compute_subset_sums(betas)

    f0, f1 = _radix(f, params.param_fft)

    deltas = [gf_square(b) ^ b for b in betas]
    u = _fft_rec(params, f0, (f_coeffs + 1) // 2, params.param_m - 1, params.param_fft - 1, deltas)
    v = _fft_rec(params, f1, f_coeffs // 2, params.param_m - 1, params.param_fft - 1, deltas)

    k = 1 << (params.param_m - 1)
    w = [0] * (2 * k)
    w[k:] = v[:2 * k]
    w[0] = u[0]
    w[k] ^= u[0]
    for i in range(1, k):
        w[i] = u[i] ^ gf_mul(betas_sums[i], v[i])
        w[k + i] ^= w[i]
    return w


def fft_retrieve_error_poly(params: HQCParameters, w: List[int]) -> List[int]:
    gammas = _compute_fft_betas(params)
    gammas_sums = _compute_subset_sums(gammas)
    error = [0] * (1 << params.param_m)

    k = 1 << (params.param_m - 1)
    error[0] ^= 1 ^ ((-w[0]) >> 15 & 1)
    error[0] ^= 1 ^ ((-w[k]) >> 15 & 1)

    for i in range(1, k):
        index = params.param_gf_mul_order - GF_LOG[gammas_sums[i]]
        error[index] ^= 1 ^ ((-w[i]) >> 15 & 1)

        index = params.param_gf_mul_order - GF_LOG[gammas_sums[i] ^ 1]
        error[index] ^= 1 ^ ((-w[k + i]) >> 15 & 1)

    return error
