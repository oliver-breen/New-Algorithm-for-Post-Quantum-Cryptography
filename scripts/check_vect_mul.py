import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from quantaweave.hqc import parameters
from quantaweave.hqc.gf2x import vect_mul
from quantaweave.hqc.byte_utils import bytes_to_u64_list, u64_list_to_bytes


def vect_mul_reference(params, a, b):
    a_bytes = u64_list_to_bytes(a, params.vec_n_size_bytes)
    b_bytes = u64_list_to_bytes(b, params.vec_n_size_bytes)
    a_int = int.from_bytes(a_bytes, "little")
    b_int = int.from_bytes(b_bytes, "little")
    prod = 0
    for bit in range(params.param_n):
        if (a_int >> bit) & 1:
            prod ^= b_int << bit
    # reduction mod x^n - 1
    modulus_mask = (1 << params.param_n) - 1
    while prod.bit_length() > params.param_n:
        overflow = prod >> params.param_n
        prod &= modulus_mask
        prod ^= overflow
    result_bytes = prod.to_bytes(params.vec_n_size_bytes, "little")
    return bytes_to_u64_list(result_bytes, params.vec_n_size_64)


def main():
    params = parameters.HQC_5
    for i in range(100):
        a = bytes_to_u64_list(os.urandom(params.vec_n_size_bytes), params.vec_n_size_64)
        b = bytes_to_u64_list(os.urandom(params.vec_n_size_bytes), params.vec_n_size_64)
        ref = vect_mul_reference(params, a, b)
        got = vect_mul(params, a, b)
        if ref != got:
            print(f"Mismatch at iteration {i}")
            print(f"a={a}")
            print(f"b={b}")
            print(f"ref={ref}")
            print(f"got={got}")
            return
    print("vect_mul matches reference for 100 random samples")


if __name__ == "__main__":
    main()
