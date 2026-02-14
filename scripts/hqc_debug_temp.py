from hashlib import sha3_512
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from quantaweave import QuantaWeave
from quantaweave.hqc.parameters import get_parameters
from quantaweave.hqc.symmetric import hash_g, hash_h, hash_j
from quantaweave.hqc.pke import hqc_pke_encrypt
from quantaweave.hqc.parsing import hqc_c_kem_to_bytes, hqc_c_kem_from_bytes, hqc_dk_pke_from_string
from quantaweave.hqc.code import code_encode, code_decode
from quantaweave.hqc.reed_solomon import reed_solomon_encode
from quantaweave.hqc.byte_utils import bytes_to_u64_list, u64_list_to_bytes
from quantaweave.hqc.vector import vect_truncate, vect_add
from quantaweave.hqc.gf2x import vect_mul
from quantaweave.hqc.vector import vect_compare


def deterministic_bytes(tag: bytes, idx: int, length: int) -> bytes:
    digest = sha3_512(tag + idx.to_bytes(4, "little")).digest()
    out = bytearray(digest)
    while len(out) < length:
        digest = sha3_512(digest).digest()
        out.extend(digest)
    return bytes(out[:length])


def debug_decaps(params, ct: bytes, dk: bytes):
    ek_pke = dk[: params.crypto_publickeybytes]
    dk_pke = dk[params.crypto_publickeybytes : params.crypto_publickeybytes + params.seed_bytes]
    sigma = dk[
        params.crypto_publickeybytes
        + params.seed_bytes : params.crypto_publickeybytes
        + params.seed_bytes
        + params.param_security_bytes
    ]

    c_pke, salt = hqc_c_kem_from_bytes(params, ct)
    y = hqc_dk_pke_from_string(params, dk_pke)
    tmp1 = vect_mul(params, y, c_pke["u"])
    tmp1 = vect_truncate(params, tmp1)
    tmp2 = vect_add(c_pke["v"], tmp1)
    m_prime_vec = code_decode(params, tmp2)
    m_prime = u64_list_to_bytes(m_prime_vec, params.param_k)

    hash_ek = hash_h(params, ek_pke)
    k_theta_prime = hash_g(params, hash_ek, m_prime, salt)
    theta_prime = k_theta_prime[params.seed_bytes : params.seed_bytes + params.seed_bytes]

    c_pke_prime = hqc_pke_encrypt(params, ek_pke, m_prime, theta_prime)
    c_kem_prime = hqc_c_kem_to_bytes(params, c_pke_prime, salt)

    k_bar = hash_j(params, hash_ek, sigma, ct)

    mismatch = vect_compare(ct, c_kem_prime)
    mask = 0xFF if mismatch == 0 else 0x00

    shared_secret = bytearray(k_theta_prime[: params.crypto_bytes])
    for i in range(params.crypto_bytes):
        shared_secret[i] = (shared_secret[i] & mask) ^ (k_bar[i] & (~mask & 0xFF))

    return {
        "shared_secret": bytes(shared_secret),
        "mismatch": mismatch,
        "message": m_prime,
        "salt": salt,
        "recomputed_ct": c_kem_prime,
        "tmp2": tmp2,
        "tmp1": tmp1,
        "y": y,
        "m_prime_vec": m_prime_vec,
    }


def main(iterations: int = 2000) -> None:
    params = get_parameters("HQC-5")
    pqc = QuantaWeave("LEVEL5")
    ek, dk = pqc.hqc_keypair()
    hash_ek = hash_h(params, ek)

    for i in range(iterations):
        m = deterministic_bytes(b"m", i, params.param_security_bytes)
        salt = deterministic_bytes(b"s", i, params.salt_bytes)
        k_theta = hash_g(params, hash_ek, m, salt)
        theta = k_theta[params.seed_bytes : params.seed_bytes + params.seed_bytes]
        c_pke = hqc_pke_encrypt(params, ek, m, theta)
        ct = hqc_c_kem_to_bytes(params, c_pke, salt)
        ss = k_theta[: params.crypto_bytes]
        debug = debug_decaps(params, ct, dk)
        ss2 = debug["shared_secret"]
        if ss != ss2:
            print(f"Mismatch at iteration {i}")
            print(f"m enc   = {m.hex()}")
            print(f"m dec   = {debug['message'].hex()}")
            print(f"salt    = {salt.hex()}")
            print(f"salt'   = {debug['salt'].hex()}")
            print(f"shared  = {ss.hex()}")
            print(f"shared' = {ss2.hex()}")
            ct_prime = debug["recomputed_ct"]
            diff = next((idx for idx, (a, b) in enumerate(zip(ct, ct_prime)) if a != b), None)
            print(f"first ciphertext diff index: {diff}")
            m_vec = bytes_to_u64_list(m, params.vec_k_size_64)
            rs_code = reed_solomon_encode(params, m_vec)
            tmp2 = debug["tmp2"]
            rm_decoded = code_decode(params, tmp2)
            print(f"RS match? {rm_decoded[:4] == rs_code[:4]}")
            return
    print(f"No mismatch after {iterations} iterations")


if __name__ == "__main__":
    main()
