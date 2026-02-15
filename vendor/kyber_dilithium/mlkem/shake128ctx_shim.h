// Shim: allow shake128_absorb to accept shake128ctx (keccak_state) pointer
static inline void shake128_absorb_ctx(shake128incctx *state, const unsigned char *input, size_t inlen) {
	shake128_absorb((uint64_t *)state->s, input, inlen);
}

// Shim: allow shake256_inc_ctx_release for ML-KEM
static inline void shake256_inc_ctx_release(shake256incctx *state) {}
// Minimal shake128ctx and shake128_ctx_release for PQClean ML-KEM integration
#include "../../hqc/lib/fips202/fips202.h"
#ifdef __cplusplus
extern "C" {
#endif
// Use shake128incctx as shake128ctx
typedef shake128incctx shake128ctx;
static inline void shake128_ctx_release(shake128ctx *state) {}

// Shim: allow shake128_squeezeblocks to accept shake128ctx (keccak_state) pointer
static inline void shake128_squeezeblocks_ctx(unsigned char *output, size_t nblocks, shake128ctx *state) {
	shake128_squeezeblocks(output, nblocks, (uint64_t *)state->s);
}
#ifdef __cplusplus
}
#endif
