"""
Generate benchmark baseline JSON by timing LWE and HQC round-trips.
"""

import json
import os
import time
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from quantaweave import QuantaWeave


def _time_lwe_level1() -> float:
    pqc = QuantaWeave("LEVEL1")
    public_key, private_key = pqc.generate_keypair()
    message = b"benchmark"
    start = time.perf_counter()
    ciphertext = pqc.encrypt(message, public_key)
    plaintext = pqc.decrypt(ciphertext, private_key)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if plaintext != message:
        raise RuntimeError("LWE round-trip failed")
    return elapsed_ms


def _time_hqc(level: str) -> float:
    pqc = QuantaWeave(level)
    start = time.perf_counter()
    public_key, private_key = pqc.hqc_keypair()
    ciphertext, shared_secret = pqc.hqc_encapsulate(public_key)
    recovered = pqc.hqc_decapsulate(ciphertext, private_key)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if recovered != shared_secret:
        raise RuntimeError(f"HQC round-trip failed for {level}")
    return elapsed_ms


def main() -> None:
    baseline = {
        "lwe_round_trip_level1": {
            "max_ms": _time_lwe_level1(),
            "notes": "Level1 LWE encrypt+decrypt",
        },
        "hqc_round_trip_level1": {
            "max_ms": _time_hqc("LEVEL1"),
            "notes": "HQC-1 KEM encaps+decaps",
        },
        "hqc_round_trip_level3": {
            "max_ms": _time_hqc("LEVEL3"),
            "notes": "HQC-3 KEM encaps+decaps",
        },
        "hqc_round_trip_level5": {
            "max_ms": _time_hqc("LEVEL5"),
            "notes": "HQC-5 KEM encaps+decaps",
        },
    }

    out_path = os.path.join(os.path.dirname(__file__), "..", "tests", "benchmarks_baseline.json")
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2)
        handle.write("\n")

    print(f"Wrote baseline to {out_path}")


if __name__ == "__main__":
    main()
