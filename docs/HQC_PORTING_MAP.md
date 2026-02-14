# HQC Porting Map

## Phase 2 Output

This document maps the HQC reference C implementation to the planned Python modules and identifies the key functions to port for HQC-128/192/256 KEM support.

## Source Tree (Reference)

- Reference implementation root: `vendor/hqc/src/ref/`
- Shared common code: `vendor/hqc/src/common/`
- Parameter sets:
  - HQC-1 (128-bit): `vendor/hqc/src/ref/hqc-1/parameters.h`, `vendor/hqc/src/common/hqc-1/api.h`
  - HQC-3 (192-bit): `vendor/hqc/src/ref/hqc-3/parameters.h`, `vendor/hqc/src/common/hqc-3/api.h`
  - HQC-5 (256-bit): `vendor/hqc/src/ref/hqc-5/parameters.h`, `vendor/hqc/src/common/hqc-5/api.h`

## Core KEM Flow (C)

- Keygen: `crypto_kem_keypair()` in `vendor/hqc/src/common/kem.c`
- Encaps: `crypto_kem_enc()` in `vendor/hqc/src/common/kem.c`
- Decaps: `crypto_kem_dec()` in `vendor/hqc/src/common/kem.c`

KEM relies on the PKE layer and parsing helpers:

- PKE keygen/encrypt/decrypt:
  - `hqc_pke_keygen`, `hqc_pke_encrypt`, `hqc_pke_decrypt` in `vendor/hqc/src/ref/hqc.c`
- Serialization:
  - `hqc_ek_pke_from_string`, `hqc_dk_pke_from_string`
  - `hqc_c_kem_to_string`, `hqc_c_kem_from_string` in `vendor/hqc/src/ref/parsing.c`

## Supporting Primitives

- Symmetric primitives and hashes:
  - `prng_init`, `prng_get_bytes`, `xof_init`, `xof_get_bytes`, `hash_g`, `hash_h`, `hash_i`, `hash_j`
  - `vendor/hqc/src/common/symmetric.c`
- Vector operations and sampling:
  - `vect_sample_fixed_weight1`, `vect_sample_fixed_weight2`, `vect_set_random`, `vect_mul`, `vect_add`, `vect_truncate`, `vect_compare`
  - `vendor/hqc/src/ref/vector.c` + `vendor/hqc/src/ref/gf2x.c`
- Code-based error correction:
  - Reed–Solomon: `vendor/hqc/src/ref/reed_solomon.c`
  - Reed–Muller: `vendor/hqc/src/ref/reed_muller.c`
  - Concatenation: `vendor/hqc/src/common/code.c`
- FFT helpers:
  - `vendor/hqc/src/common/fft.c`
- Galois field arithmetic:
  - `vendor/hqc/src/ref/gf.c`

## Proposed Python Module Layout

Target location: `quantaweave/hqc/`

- `quantaweave/hqc/parameters.py`
  - Parse constants from C parameters (HQC-1/3/5)
- `quantaweave/hqc/symmetric.py`
  - SHAKE/SHA3 wrappers, XOF, hash functions (G/H/I/J), PRNG
- `quantaweave/hqc/vector.py`
  - Fixed-weight sampling, vector ops, truncate, compare
- `quantaweave/hqc/gf.py`
  - GF(2^8) arithmetic (mul/square/inverse)
- `quantaweave/hqc/gf2x.py`
  - GF(2)[x] multiplication + reduction (Karatsuba + schoolbook)
- `quantaweave/hqc/reed_solomon.py`
  - RS encode/decode (Berlekamp + FFT)
- `quantaweave/hqc/reed_muller.py`
  - RM(1,7) encode/decode
- `quantaweave/hqc/code.py`
  - Concatenated code encode/decode (RS + RM)
- `quantaweave/hqc/parsing.py`
  - Serialization helpers for PKE/KEM
- `quantaweave/hqc/pke.py`
  - `hqc_pke_keygen`, `hqc_pke_encrypt`, `hqc_pke_decrypt`
- `quantaweave/hqc/kem.py`
  - `hqc_kem_keypair`, `hqc_kem_encapsulate`, `hqc_kem_decapsulate`

## Parameter Sets and Sizes

From `api.h` (NIST KEM API):

- HQC-1:
  - `CRYPTO_PUBLICKEYBYTES` = 2241
  - `CRYPTO_SECRETKEYBYTES` = 2321
  - `CRYPTO_CIPHERTEXTBYTES` = 4433
  - `CRYPTO_BYTES` = 32
- HQC-3:
  - `CRYPTO_PUBLICKEYBYTES` = 4514
  - `CRYPTO_SECRETKEYBYTES` = 4602
  - `CRYPTO_CIPHERTEXTBYTES` = 8978
  - `CRYPTO_BYTES` = 32
- HQC-5:
  - `CRYPTO_PUBLICKEYBYTES` = 7237
  - `CRYPTO_SECRETKEYBYTES` = 7333
  - `CRYPTO_CIPHERTEXTBYTES` = 14421
  - `CRYPTO_BYTES` = 32

## Next Implementation Steps (Phase 3)

1. Port parameter constants into `quantaweave/hqc/parameters.py`.
2. Implement SHAKE/SHA3-based XOF and hash functions.
3. Port vector sampling and multiplication primitives.
4. Port Reed–Solomon and Reed–Muller codecs.
5. Implement PKE, then KEM wrapper.
6. Add tests for KEM round-trip across HQC-1/3/5.

## Notes

- The reference implementation uses constant-time tricks and bit-level operations; Python ports will be slower.
- Maintain identical serialization layouts to match NIST KEM API sizes.
- Avoid SIMD/AVX optimizations; port only the reference code path.
