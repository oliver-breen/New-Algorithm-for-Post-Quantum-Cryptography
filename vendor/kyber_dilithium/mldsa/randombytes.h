// Minimal randombytes.h for PQClean Dilithium integration
// Uses C standard library for random bytes
#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void randombytes(unsigned char *out, size_t outlen);
#ifdef __cplusplus
}
#endif
#endif // RANDOMBYTES_H
