## 🖥️ QuantaWeave GUI

### Unified PQ Suite Tab

The GUI now features a **PQ Suite** tab, providing a unified interface for post-quantum KEM and signature operations. You can select Kyber or HQC for KEM, and Dilithium or Falcon for signatures, at any security level. Generate keypairs, encapsulate/decapsulate shared secrets, and sign/verify messages—all from one place.

**How to use:**
1. Go to the PQ Suite tab.
2. Select your desired KEM, signature, and security level.
3. Generate KEM and signature keypairs.
4. Use the Encapsulate/Decapsulate and Sign/Verify buttons as needed.

This makes it easy to experiment with and compare different post-quantum cryptography standards in a single workflow.

The QuantaWeave GUI provides a graphical interface for LWE encryption, HQC KEM, and Falcon signatures.

### Launching the GUI

- Install dependencies:
	```bash
	python -m pip install .[gui]
	```
- Run from source:
	```bash
	python gui/quantaweave_gui.py
	```
- Or run the standalone EXE if built with PyInstaller.

### Features

- **LWE Tab:** Key generation, encryption, and decryption with selectable security level.
- **HQC KEM Tab:** Keypair, encapsulation, and decapsulation with encoding options.
- **Falcon Tab:** Falcon-512/1024 keygen, sign, and verify.

### Step-by-Step Example (LWE)
1. Go to the LWE tab.
2. Select security level and click Generate Keypair.
3. Enter a message and click Encrypt.
4. Paste ciphertext and private key, click Decrypt to recover the message.

See [docs/GUI.md](docs/GUI.md) for a full illustrated guide and more examples.
# QuantaWeave Post-Quantum Cryptography

QuantaWeave is a Python implementation of a lattice-based post-quantum cryptographic system designed to be secure against quantum computer attacks, plus supporting demos and documentation.

## 🔐 Overview

This project implements a post-quantum encryption scheme based on the **Learning With Errors (LWE)** problem, which is believed to be hard even for quantum computers. It also includes a code-based **HQC KEM** implementation for shared-secret encapsulation and a Falcon signature binding, plus examples and documentation for experimentation.

## ✨ Key Features

- **Quantum-Resistant Security**: Based on hard lattice problems
- **Multiple Security Levels**: 128-bit, 192-bit, and 256-bit security options
- **Pure Python Core**: No external dependencies for the LWE-based library in `quantaweave/`
- **Falcon Signatures**: C++ binding for Falcon-512/1024 signatures
- **Simple API**: Easy-to-use interface for developers
- **Examples Included**: Basic, benchmark, multi-party, HQC KEM, and Falcon signature demos
- **Comprehensive Testing**: Unit tests for math, keygen, and encryption
- **Well-Documented**: Algorithm and security references

## 🚀 Quick Start

```python
from quantaweave import QuantaWeave

# Initialize the system
pqc = QuantaWeave(security_level='LEVEL1')

# Generate keys
public_key, private_key = pqc.generate_keypair()

# Encrypt a message
message = b"Hello, Quantum World!"
ciphertext = pqc.encrypt(message, public_key)

# Decrypt
plaintext = pqc.decrypt(ciphertext, private_key)
print(plaintext)  # b'Hello, Quantum World!'
```

## 📚 Documentation

- [Algorithm Details](docs/ALGORITHM.md) - Comprehensive algorithm description
- [API Reference](docs/ALGORITHM.md#api-reference) - Complete API documentation
- [Security Analysis](docs/SECURITY.md) - Security considerations and threat model
- [Production Guidance](docs/PRODUCTION.md) - Hardening and release practices
- [Release Process](docs/RELEASE.md) - Versioning and release checklist

## 🧩 API Reference (Quick)

`QuantaWeave` methods:

- `generate_keypair()` - Generate LWE public/private keys
- `encrypt(message, public_key)` - Encrypt bytes with LWE public key
- `decrypt(ciphertext, private_key)` - Decrypt LWE ciphertext
- `get_security_level()` - Return configured security level
- `hqc_keypair()` - Generate HQC KEM public/private keys
- `hqc_encapsulate(public_key)` - Encapsulate shared secret (HQC)
- `hqc_decapsulate(ciphertext, private_key)` - Decapsulate shared secret (HQC)

`FalconSig` methods:

- `keygen()` - Generate Falcon public/private keys
- `sign(secret_key, message)` - Sign a message
- `verify(public_key, message, signature)` - Verify a signature
- `sizes()` - Return key/signature sizes

HQC sizes (bytes):

| HQC Variant | Public Key | Private Key | Ciphertext | Shared Secret |
|-------------|------------|-------------|------------|---------------|
| HQC-1 | 2241 | 2321 | 4433 | 32 |
| HQC-3 | 4514 | 4602 | 8978 | 32 |
| HQC-5 | 7237 | 7333 | 14421 | 32 |

## 🧪 Running Tests

```bash
python -m unittest tests/test_quantaweave.py -v
python -m unittest tests/test_kem_tests.py -v
python -m unittest tests/test_hqc_kem.py -v
python -m unittest tests/test_falcon_sig.py -v

# Optional benchmarks (set RUN_BENCHMARKS=1)
# Use BENCHMARK_USE_BASELINE=1 to enforce tests/benchmarks_baseline.json
RUN_BENCHMARKS=1 python -m unittest tests/test_benchmarks.py -v

# Regenerate the benchmark baseline JSON
python scripts/generate_benchmark_baseline.py
```

## 📊 Examples

Command-line:

```bash
# Basic usage demonstration
python examples/basic_usage.py

# Performance benchmarks
python examples/benchmark.py

# Multi-party messaging demo
python examples/multi_party.py

# HQC KEM demo
python examples/hqc_kem_usage.py

# Falcon signature demo (requires GMP + C++ build)
python examples/falcon_signature.py
```

Python snippets:

```python
from quantaweave import QuantaWeave

pqc = QuantaWeave(security_level="LEVEL3")
public_key, private_key = pqc.hqc_keypair()
ciphertext, shared_secret = pqc.hqc_encapsulate(public_key)
recovered = pqc.hqc_decapsulate(ciphertext, private_key)
assert recovered == shared_secret
```

```python
from quantaweave import FalconSig

falcon = FalconSig("Falcon-1024")
public_key, secret_key = falcon.keygen()
message = b"sign me"
signature = falcon.sign(secret_key, message)
assert falcon.verify(public_key, message, signature)
```

## 🪟 Windows GUI

Run the GUI (ensures PyQt6 is installed):

```bash
python -m pip install .[gui]
python gui/quantaweave_gui.py
```

Build the signed bootloader + one-file executable:

```bash
python -m pip install .[gui]
pyinstaller --noconfirm --clean QuantaWeaveGUI.spec
# output: dist/QuantaWeaveGUI.exe (icon embedded if assets/quantaweave.ico exists)
```

PyInstaller leaves detailed logs in `build/QuantaWeaveGUI/`. If Windows Defender locks `build/QuantaWeaveGUI/localpycs`, delete the `build/` directory before re-running.

### Automated Builds & Code Signing

The GitHub Actions workflow now produces Windows artifacts (EXE, installer, ZIP) via the `build-windows` job. Optional code signing happens when two repository secrets are configured:

- `CODE_SIGNING_CERT`: Base64 representation of your `.pfx` certificate (see below).
- `CODE_SIGNING_PASSWORD`: Password protecting the `.pfx` file.

Create the Base64 payload with PowerShell:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("path/to/codesign.pfx")) |
	Set-Content -NoNewline codesign.b64
```

Copy the single-line contents of `codesign.b64` into the `CODE_SIGNING_CERT` secret, then delete the intermediate file. When both secrets exist, the workflow signs `dist/QuantaWeaveGUI.exe` and `dist/QuantaWeaveGUI-Setup.exe` using `signtool` with a RFC 3161 timestamp.

To test the workflow without real credentials, trigger the `ci` workflow manually (`Actions` → `ci` → **Run workflow**) and set **use_dummy_signing** to `true`. The pipeline will mint a short-lived self-signed certificate on the runner so the signing step executes end-to-end without touching your production keys.

## 🛠️ Building the Falcon Extension (Required for Falcon Signatures)

The Falcon signature scheme requires a native C++ extension (`quantaweave._falcon`). If you see an error like:

> Falcon extension is not available. Build from source with GMP and pybind11.

You must build the extension before Falcon signatures will work in the GUI or Python API.

### Prerequisites

- **GMP** (GNU Multiple Precision Arithmetic Library)
- **pybind11** (Python bindings for C++)
- **C++20 compiler** (MSVC, clang, or gcc)

Install pybind11:

```bash
python -m pip install pybind11
```

#### Windows: Install GMP
- Download GMP for Windows (e.g., from MSYS2 or prebuilt binaries)
- Set environment variables before building:
	- `GMP_INCLUDE_DIR` (e.g., `C:/msys64/mingw64/include`)
	- `GMP_LIB_DIR` (e.g., `C:/msys64/mingw64/lib`)

#### Linux/macOS: Install GMP
- Use your package manager:
	- Ubuntu: `sudo apt-get install libgmp-dev`
	- macOS: `brew install gmp`

### Build the Falcon extension

From the project root:

```bash
python setup.py build_ext --inplace
# or, for editable install:
python -m pip install -e .[dev]
```

If successful, you should see a file like `quantaweave/_falcon.*.so` (Linux/macOS) or `.pyd` (Windows).

### Troubleshooting

- **ImportError:**
	- Make sure you are using the correct Python environment.
	- Check that `pybind11` and `gmp` are installed and visible to your compiler.
- **MSVC errors:**
	- Ensure you have a recent Visual Studio with C++20 support.
	- Set the correct `GMP_INCLUDE_DIR` and `GMP_LIB_DIR`.
- **Linker errors:**
	- Confirm that the GMP library is found and matches your compiler architecture (x64 vs x86).
- **Still stuck?**
	- See `setup.py` for build logic and environment variables.
	- Open an issue with your build log and platform details.

Once built, restart the GUI or your Python session. Falcon signatures should now work.

## 🏗️ Project Structure

```
├── quantaweave/           # Main library (LWE-based)
│   ├── core.py         # Main API
│   ├── keygen.py       # Key generation
│   ├── encryption.py   # Encryption/decryption
│   ├── math_utils.py   # Mathematical utilities
│   └── parameters.py   # Security parameters
│   ├── falcon.py       # Falcon signature wrapper
│   └── _falcon_bindings.cpp  # C++ binding source
│   └── hqc/            # HQC KEM implementation
├── tests/              # Test suite
├── examples/           # Usage examples
└── docs/               # Documentation
encapsulation_decapsulation.py  # RSA-OAEP key wrap demo (classical)
key_generation.py               # RSA key generation demo (disabled by default)
kyber_dilithium_hqc.py          # Placeholders for future integration
results_v2.md                   # Baseline KEM test template
```

## 🔬 Algorithm Design

The algorithm uses:
- **Polynomial Ring**: R_q = Z_q[X]/(X^n + 1)
- **LWE Problem**: Hard problem forming security foundation
- **Centered Binomial Sampling**: For generating secure noise
- **Compression**: To reduce ciphertext size

See [Algorithm Details](docs/ALGORITHM.md) for more information.

## ⚠️ Security Notice

This is an **educational implementation**. For production use:

1. Use NIST-standardized algorithms (Kyber, Dilithium)
2. Obtain professional security audits
3. Implement constant-time operations
4. Consider side-channel attack resistance

**DO NOT USE IN PRODUCTION WITHOUT PROFESSIONAL SECURITY REVIEW**

## 📌 Notes on Demos and Placeholders

- The `encapsulation_decapsulation.py` demo uses RSA-OAEP for key wrapping, which is **not** post-quantum secure. It is provided for hybrid KEM workflow illustration only.
- Dependencies: the RSA demo requires the `cryptography` package (the LWE core in `quantaweave/` does not).
- The `key_generation.py` file is currently a disabled RSA keygen example (wrapped in a docstring).
- `kyber_dilithium_hqc.py` contains placeholders only and does not implement those schemes.
- `results_v2.md` contains a baseline test template with sample data, not verified benchmarks.
- Falcon signatures use a C++ extension and require GMP, pybind11, and a C++20 compiler to build.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

## 👤 Author

Oliver Breen

## 🤝 Contributing

Contributions are welcome! Please ensure all tests pass and documentation is updated.