"""
HQC key encapsulation mechanism (KEM).

Ported from kem.c.
"""

from typing import Tuple
import secrets

from .parameters import HQCParameters
from .symmetric import hash_g, hash_h, hash_j, xof_init
from .pke import hqc_pke_keygen, hqc_pke_encrypt, hqc_pke_decrypt
from .parsing import hqc_c_kem_to_bytes, hqc_c_kem_from_bytes
from .vector import vect_compare


def hqc_kem_keypair(params: HQCParameters) -> Tuple[bytes, bytes]:
    seed_kem = secrets.token_bytes(params.seed_bytes)
    xof = xof_init(seed_kem)
    seed_pke = xof.get_bytes(params.seed_bytes)
    sigma = xof.get_bytes(params.param_security_bytes)

    ek_pke, dk_pke = hqc_pke_keygen(params, seed_pke)
    ek_kem = ek_pke
    dk_kem = ek_kem + dk_pke + sigma + seed_kem

    return ek_kem, dk_kem


def hqc_kem_encaps(params: HQCParameters, ek_kem: bytes) -> Tuple[bytes, bytes]:
    m = secrets.token_bytes(params.param_security_bytes)
    salt = secrets.token_bytes(params.salt_bytes)

    hash_ek_kem = hash_h(params, ek_kem)
    k_theta = hash_g(params, hash_ek_kem, m, salt)
    theta = k_theta[params.seed_bytes : params.seed_bytes + params.seed_bytes]

    c_pke = hqc_pke_encrypt(params, ek_kem, m, theta)
    c_kem = hqc_c_kem_to_bytes(params, c_pke, salt)

    shared_secret = k_theta[: params.crypto_bytes]
    return c_kem, shared_secret


def hqc_kem_decaps(params: HQCParameters, c_kem: bytes, dk_kem: bytes) -> bytes:
    ek_pke = dk_kem[: params.crypto_publickeybytes]
    dk_pke = dk_kem[params.crypto_publickeybytes : params.crypto_publickeybytes + params.seed_bytes]
    sigma = dk_kem[
        params.crypto_publickeybytes + params.seed_bytes : params.crypto_publickeybytes + params.seed_bytes + params.param_security_bytes
    ]

    c_pke, salt = hqc_c_kem_from_bytes(params, c_kem)
    m_prime = hqc_pke_decrypt(params, dk_pke, c_pke)

    hash_ek_kem = hash_h(params, ek_pke)
    k_theta_prime = hash_g(params, hash_ek_kem, m_prime, salt)
    theta_prime = k_theta_prime[params.seed_bytes : params.seed_bytes + params.seed_bytes]

    c_pke_prime = hqc_pke_encrypt(params, ek_pke, m_prime, theta_prime)
    c_kem_prime = hqc_c_kem_to_bytes(params, c_pke_prime, salt)

    k_bar = hash_j(params, hash_ek_kem, sigma, c_kem)

    mismatch = vect_compare(c_kem, c_kem_prime)
    mask = 0xFF if mismatch == 0 else 0x00

    shared_secret = bytearray(k_theta_prime[: params.crypto_bytes])
    for i in range(params.crypto_bytes):
        shared_secret[i] = (shared_secret[i] & mask) ^ (k_bar[i] & (~mask & 0xFF))

    return bytes(shared_secret)
