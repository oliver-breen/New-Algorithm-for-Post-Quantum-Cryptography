// Minimal randombytes.c for PQClean Dilithium integration
#include "randombytes.h"
#include <stdlib.h>
void randombytes(unsigned char *out, size_t outlen) {
    for (size_t i = 0; i < outlen; ++i) {
        out[i] = (unsigned char)(rand() & 0xFF);
    }
}
