/*
 * Minimal FIPS 202 SHAKE implementation (public domain, derived from PQClean's fips202).
 */

#include "fips202.h"

#include <string.h>

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
};

static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
};

static void keccakf1600_statepermute(uint64_t *state)
{
    for (int round = 0; round < 24; ++round) {
        uint64_t bc[5];
        for (int i = 0; i < 5; ++i) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for (int i = 0; i < 5; ++i) {
            uint64_t t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
            for (int j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }

        uint64_t temp = state[1];
        for (int i = 0; i < 24; ++i) {
            int idx = keccakf_piln[i];
            uint64_t current = state[idx];
            state[idx] = (temp << keccakf_rotc[i]) | (temp >> (64 - keccakf_rotc[i]));
            temp = current;
        }

        for (int j = 0; j < 25; j += 5) {
            uint64_t temp_a[5];
            for (int i = 0; i < 5; ++i) {
                temp_a[i] = state[j + i];
            }
            for (int i = 0; i < 5; ++i) {
                state[j + i] ^= (~temp_a[(i + 1) % 5]) & temp_a[(i + 2) % 5];
            }
        }

        state[0] ^= keccakf_rndc[round];
    }
}

static void keccak_absorb(uint64_t *state, size_t rate, const unsigned char *input, size_t inlen, unsigned char domain)
{
    size_t i;
    while (inlen >= rate) {
        for (i = 0; i < rate / 8; ++i) {
            uint64_t t = 0;
            for (size_t j = 0; j < 8; ++j) {
                t |= (uint64_t)input[8 * i + j] << (8 * j);
            }
            state[i] ^= t;
        }
        keccakf1600_statepermute(state);
        input += rate;
        inlen -= rate;
    }

    unsigned char temp[SHAKE128_RATE];
    memset(temp, 0, sizeof temp);
    memcpy(temp, input, inlen);
    temp[inlen] = domain;
    temp[rate - 1] |= 0x80;
    for (i = 0; i < rate / 8; ++i) {
        uint64_t t = 0;
        for (size_t j = 0; j < 8; ++j) {
            t |= (uint64_t)temp[8 * i + j] << (8 * j);
        }
        state[i] ^= t;
    }
}

static void keccak_squeezeblocks_impl(unsigned char *output, size_t nblocks, size_t rate, uint64_t *state)
{
    for (size_t block = 0; block < nblocks; ++block) {
        for (size_t i = 0; i < rate / 8; ++i) {
            uint64_t t = state[i];
            for (size_t j = 0; j < 8; ++j) {
                output[8 * i + j] = (unsigned char)(t >> (8 * j));
            }
        }
        output += rate;
        if (block + 1 < nblocks) {
            keccakf1600_statepermute(state);
        }
    }
}

void keccak_squeezeblocks(unsigned char *output, size_t nblocks, size_t rate, uint64_t *state)
{
    keccak_squeezeblocks_impl(output, nblocks, rate, state);
}

void shake128_absorb(uint64_t *state, const unsigned char *input, size_t inlen)
{
    memset(state, 0, 25 * sizeof(uint64_t));
    keccak_absorb(state, SHAKE128_RATE, input, inlen, 0x1F);
}

void shake128_squeezeblocks(unsigned char *output, size_t nblocks, uint64_t *state)
{
    keccak_squeezeblocks_impl(output, nblocks, SHAKE128_RATE, state);
}

void shake256_absorb(uint64_t *state, const unsigned char *input, size_t inlen)
{
    memset(state, 0, 25 * sizeof(uint64_t));
    keccak_absorb(state, SHAKE256_RATE, input, inlen, 0x1F);
}

void shake256_squeezeblocks(unsigned char *output, size_t nblocks, uint64_t *state)
{
    keccak_squeezeblocks_impl(output, nblocks, SHAKE256_RATE, state);
}

static void shake(unsigned char *output, size_t outlen, size_t rate, const unsigned char *input, size_t inlen)
{
    uint64_t state[25] = {0};
    keccak_absorb(state, rate, input, inlen, 0x1F);
    while (outlen > rate) {
        keccak_squeezeblocks_impl(output, 1, rate, state);
        output += rate;
        outlen -= rate;
        keccakf1600_statepermute(state);
    }
    unsigned char block[SHAKE128_RATE];
    keccak_squeezeblocks_impl(block, 1, rate, state);
    memcpy(output, block, outlen);
}

void shake128(unsigned char *output, size_t outlen, const unsigned char *input, size_t inlen)
{
    shake(output, outlen, SHAKE128_RATE, input, inlen);
}

void shake256(unsigned char *output, size_t outlen, const unsigned char *input, size_t inlen)
{
    shake(output, outlen, SHAKE256_RATE, input, inlen);
}

static void shake_inc_init(keccak_state *state)
{
    memset(state->s, 0, sizeof state->s);
    state->pos = 0;
}

static void shake_inc_absorb(keccak_state *state, size_t rate, const unsigned char *input, size_t inlen)
{
    while (inlen > 0) {
        size_t to_take = rate - state->pos;
        if (to_take > inlen) {
            to_take = inlen;
        }
        for (size_t i = 0; i < to_take; ++i) {
            size_t idx = (state->pos + i) / 8;
            size_t shift = ((state->pos + i) % 8) * 8;
            state->s[idx] ^= (uint64_t)input[i] << shift;
        }
        state->pos += to_take;
        input += to_take;
        inlen -= to_take;
        if (state->pos == rate) {
            keccakf1600_statepermute(state->s);
            state->pos = 0;
        }
    }
}

static void shake_inc_finalize(keccak_state *state, size_t rate, unsigned char domain)
{
    size_t idx = state->pos / 8;
    size_t shift = (state->pos % 8) * 8;
    state->s[idx] ^= (uint64_t)domain << shift;
    idx = (rate - 1) / 8;
    shift = ((rate - 1) % 8) * 8;
    state->s[idx] ^= (uint64_t)1ULL << shift;
    keccakf1600_statepermute(state->s);
    state->pos = rate;
}

static void shake_inc_squeeze(unsigned char *output, size_t outlen, size_t rate, keccak_state *state)
{
    size_t offset = 0;
    while (outlen > 0) {
        if (state->pos == rate) {
            keccakf1600_statepermute(state->s);
            state->pos = 0;
        }
        size_t to_take = rate - state->pos;
        if (to_take > outlen) {
            to_take = outlen;
        }
        for (size_t i = 0; i < to_take; ++i) {
            size_t idx = (state->pos + i) / 8;
            size_t shift = ((state->pos + i) % 8) * 8;
            output[offset + i] = (unsigned char)(state->s[idx] >> shift);
        }
        state->pos += to_take;
        outlen -= to_take;
        offset += to_take;
    }
}

void shake128_inc_init(shake128incctx *state)
{
    shake_inc_init(state);
}

void shake128_inc_absorb(shake128incctx *state, const unsigned char *input, size_t inlen)
{
    shake_inc_absorb(state, SHAKE128_RATE, input, inlen);
}

void shake128_inc_finalize(shake128incctx *state)
{
    shake_inc_finalize(state, SHAKE128_RATE, 0x1F);
}

void shake128_inc_squeeze(unsigned char *output, size_t outlen, shake128incctx *state)
{
    shake_inc_squeeze(output, outlen, SHAKE128_RATE, state);
}

void shake256_inc_init(shake256incctx *state)
{
    shake_inc_init(state);
}

void shake256_inc_absorb(shake256incctx *state, const unsigned char *input, size_t inlen)
{
    shake_inc_absorb(state, SHAKE256_RATE, input, inlen);
}

void shake256_inc_finalize(shake256incctx *state)
{
    shake_inc_finalize(state, SHAKE256_RATE, 0x1F);
}

void shake256_inc_squeeze(unsigned char *output, size_t outlen, shake256incctx *state)
{
    shake_inc_squeeze(output, outlen, SHAKE256_RATE, state);
}

static void sha3_inc_init(keccak_state *state)
{
    shake_inc_init(state);
}

static void sha3_inc_absorb(keccak_state *state, size_t rate, const unsigned char *input, size_t inlen)
{
    shake_inc_absorb(state, rate, input, inlen);
}

static void sha3_inc_finalize(unsigned char *output, size_t rate, keccak_state *state)
{
    shake_inc_finalize(state, rate, 0x06);
    unsigned char block[SHAKE128_RATE];
    keccak_squeezeblocks_impl(block, 1, rate, state->s);
    memcpy(output, block, rate);
}

void sha3_256_inc_init(sha3_256incctx *state)
{
    sha3_inc_init(state);
}

void sha3_256_inc_absorb(sha3_256incctx *state, const unsigned char *input, size_t inlen)
{
    sha3_inc_absorb(state, SHA3_256_RATE, input, inlen);
}

void sha3_256_inc_finalize(unsigned char *output, sha3_256incctx *state)
{
    unsigned char block[SHA3_256_RATE];
    shake_inc_finalize(state, SHA3_256_RATE, 0x06);
    keccak_squeezeblocks_impl(block, 1, SHA3_256_RATE, state->s);
    memcpy(output, block, 32);
}

void sha3_256(unsigned char *output, const unsigned char *input, size_t inlen)
{
    keccak_state state;
    shake_inc_init(&state);
    sha3_inc_absorb(&state, SHA3_256_RATE, input, inlen);
    sha3_256_inc_finalize(output, &state);
}

void sha3_512_inc_init(sha3_512incctx *state)
{
    sha3_inc_init(state);
}

void sha3_512_inc_absorb(sha3_512incctx *state, const unsigned char *input, size_t inlen)
{
    sha3_inc_absorb(state, SHA3_512_RATE, input, inlen);
}

void sha3_512_inc_finalize(unsigned char *output, sha3_512incctx *state)
{
    unsigned char block[SHA3_512_RATE];
    shake_inc_finalize(state, SHA3_512_RATE, 0x06);
    keccak_squeezeblocks_impl(block, 1, SHA3_512_RATE, state->s);
    memcpy(output, block, 64);
}

void sha3_512(unsigned char *output, const unsigned char *input, size_t inlen)
{
    keccak_state state;
    shake_inc_init(&state);
    sha3_inc_absorb(&state, SHA3_512_RATE, input, inlen);
    sha3_512_inc_finalize(output, &state);
}
