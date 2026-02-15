
// kyber_dilithium_bindings.cpp
// Pybind11 wrapper for Kyber (ML-KEM) and Dilithium (ML-DSA)
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <cstring>

#include "mlkem/kem.h"
#include "mldsa/sign.h"

namespace py = pybind11;

// Kyber (ML-KEM-512) minimal wrapper
py::dict kyber_keygen() {
    unsigned char pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    py::dict result;
    result["public_key"] = py::bytes(reinterpret_cast<const char*>(pk), PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    result["secret_key"] = py::bytes(reinterpret_cast<const char*>(sk), PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);
    return result;
}

py::dict kyber_encaps(const py::bytes &pk) {
    unsigned char ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    std::string pk_str = pk;
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(reinterpret_cast<unsigned char*>(ct), reinterpret_cast<unsigned char*>(ss), reinterpret_cast<const unsigned char*>(pk_str.data()));
    py::dict result;
    result["ciphertext"] = py::bytes(reinterpret_cast<const char*>(ct), PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    result["shared_secret"] = py::bytes(reinterpret_cast<const char*>(ss), PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);
    return result;
}

py::bytes kyber_decaps(const py::bytes &ct, const py::bytes &sk) {
    unsigned char ss[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    std::string ct_str = ct;
    std::string sk_str = sk;
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(reinterpret_cast<unsigned char*>(ss), reinterpret_cast<const unsigned char*>(ct_str.data()), reinterpret_cast<const unsigned char*>(sk_str.data()));
    return py::bytes(reinterpret_cast<const char*>(ss), PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);
}

// Dilithium (ML-DSA-44) minimal wrapper
py::dict dilithium_keygen() {
    unsigned char pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];
    PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
    py::dict result;
    result["public_key"] = py::bytes(reinterpret_cast<const char*>(pk), PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES);
    result["secret_key"] = py::bytes(reinterpret_cast<const char*>(sk), PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES);
    return result;
}

py::bytes dilithium_sign(const py::bytes &sk, const py::bytes &msg) {
    unsigned char sig[PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES];
    unsigned long long siglen;
    std::string sk_str = sk;
    std::string msg_str = msg;
    PQCLEAN_MLDSA44_CLEAN_crypto_sign(reinterpret_cast<unsigned char*>(sig), &siglen, reinterpret_cast<const unsigned char*>(msg_str.data()), msg_str.size(), reinterpret_cast<const unsigned char*>(sk_str.data()));
    return py::bytes(reinterpret_cast<const char*>(sig), siglen);
}

bool dilithium_verify(const py::bytes &pk, const py::bytes &msg, const py::bytes &sig) {
    std::string pk_str = pk;
    std::string msg_str = msg;
    std::string sig_str = sig;
    int ret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(reinterpret_cast<const unsigned char*>(sig_str.data()), sig_str.size(), reinterpret_cast<const unsigned char*>(msg_str.data()), msg_str.size(), reinterpret_cast<const unsigned char*>(pk_str.data()));
    return ret == 0;
}

PYBIND11_MODULE(_kyber_dilithium, m) {
    m.def("kyber_keygen", &kyber_keygen);
    m.def("kyber_encaps", &kyber_encaps);
    m.def("kyber_decaps", &kyber_decaps);
    m.def("dilithium_keygen", &dilithium_keygen);
    m.def("dilithium_sign", &dilithium_sign);
    m.def("dilithium_verify", &dilithium_verify);
}
