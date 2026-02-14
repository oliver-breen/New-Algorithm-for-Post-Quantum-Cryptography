/*
 * Minimal FIPS 202 SHAKE implementation (public domain, based on TweetFips202).
 */

#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t s[25];
    unsigned int pos;
} keccak_state;

typedef keccak_state shake128incctx;
typedef keccak_state shake256incctx;
typedef keccak_state sha3_256incctx;
typedef keccak_state sha3_512incctx;

void shake128_absorb(uint64_t *state, const unsigned char *input, size_t inlen);
void shake128_squeezeblocks(unsigned char *output, size_t nblocks, uint64_t *state);
void shake256_absorb(uint64_t *state, const unsigned char *input, size_t inlen);
void shake256_squeezeblocks(unsigned char *output, size_t nblocks, uint64_t *state);
void keccak_squeezeblocks(unsigned char *output, size_t nblocks, size_t rate, uint64_t *state);

void shake128(unsigned char *output, size_t outlen, const unsigned char *input, size_t inlen);
void shake256(unsigned char *output, size_t outlen, const unsigned char *input, size_t inlen);

void shake128_inc_init(shake128incctx *state);
void shake128_inc_absorb(shake128incctx *state, const unsigned char *input, size_t inlen);
void shake128_inc_finalize(shake128incctx *state);
void shake128_inc_squeeze(unsigned char *output, size_t outlen, shake128incctx *state);

void shake256_inc_init(shake256incctx *state);
void shake256_inc_absorb(shake256incctx *state, const unsigned char *input, size_t inlen);
void shake256_inc_finalize(shake256incctx *state);
void shake256_inc_squeeze(unsigned char *output, size_t outlen, shake256incctx *state);

void sha3_256_inc_init(sha3_256incctx *state);
void sha3_256_inc_absorb(sha3_256incctx *state, const unsigned char *input, size_t inlen);
void sha3_256_inc_finalize(unsigned char *output, sha3_256incctx *state);
void sha3_256(unsigned char *output, const unsigned char *input, size_t inlen);

void sha3_512_inc_init(sha3_512incctx *state);
void sha3_512_inc_absorb(sha3_512incctx *state, const unsigned char *input, size_t inlen);
void sha3_512_inc_finalize(unsigned char *output, sha3_512incctx *state);
void sha3_512(unsigned char *output, const unsigned char *input, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif /* FIPS202_H */
