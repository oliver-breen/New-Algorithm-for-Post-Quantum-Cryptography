from quantaweave.pq_schemes import KyberScheme, DilithiumScheme, HQCScheme, UnifiedPQHybrid

def main():
    # Instantiate individual schemes
    kyber = KyberScheme()
    hqc = HQCScheme(param_set="HQC-1")
    dilithium = DilithiumScheme()

    # Create a hybrid: Kyber + HQC for KEM, Dilithium for signature
    hybrid = UnifiedPQHybrid(kem_schemes=[kyber, hqc], sig_schemes=[dilithium])

    # Key generation
    pub_keys, sec_keys = hybrid.generate_keypair()
    print("Public keys:", pub_keys)
    print("Secret keys:", sec_keys)

    # KEM: Encapsulation/Decapsulation
    ciphertexts, shared_secret = hybrid.encapsulate(pub_keys)
    print("Ciphertexts:", ciphertexts)
    print("Combined shared secret:", shared_secret.hex())

    recovered_secret = hybrid.decapsulate(ciphertexts, sec_keys)
    print("Recovered shared secret:", recovered_secret.hex())
    assert shared_secret == recovered_secret, "Shared secret mismatch!"

    # Signature: Sign/Verify
    message = b"Test message for hybrid PQ scheme."
    signatures = hybrid.sign(message, sec_keys)
    print("Signatures:", signatures)
    valid = hybrid.verify(message, signatures, pub_keys)
    print("Signature valid:", valid)
    assert valid, "Signature verification failed!"

if __name__ == "__main__":
    main()
