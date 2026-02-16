import os

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as _build_ext

import pybind11

<<<<<<< Updated upstream
# Initialize from environment variables
=======

# Check for local GMP directories if environment variables are not set
if not gmp_include and os.path.exists("gmp_include"):
    gmp_include = os.path.abspath("gmp_include")

if not gmp_lib and os.path.exists("gmp_libs"):
    gmp_lib = os.path.abspath("gmp_libs")

>>>>>>> Stashed changes
gmp_include = os.environ.get("GMP_INCLUDE_DIR")
gmp_lib = os.environ.get("GMP_LIB_DIR")

# Fallback to local directories if environment variables are not set
if not gmp_include and os.path.exists("gmp_include"):
    gmp_include = os.path.abspath("gmp_include")

if not gmp_lib and os.path.exists("gmp_libs"):
    gmp_lib = os.path.abspath("gmp_libs")


# Falcon build config
falcon_include_dirs = [
    pybind11.get_include(),
    pybind11.get_include(True),
    "vendor/falcon/include",
    "vendor/hqc/lib/fips202",
]
if gmp_include:
    falcon_include_dirs.append(gmp_include)

falcon_library_dirs = []
if gmp_lib:
    falcon_library_dirs.append(gmp_lib)

falcon_extension = Extension(
    "quantaweave._falcon",
    sources=[
        "quantaweave/_falcon_bindings.cpp",
        "quantaweave/_fips202_wrapper.cpp",
    ],
    include_dirs=falcon_include_dirs,
    library_dirs=falcon_library_dirs,
    language="c++",
    extra_compile_args=["-std=c++20"],
    libraries=["gmp", "gmpxx"],
)


# Kyber/Dilithium build config
kyber_dilithium_include_dirs = [
    pybind11.get_include(),
    pybind11.get_include(True),
    "vendor/kyber_dilithium",
    "vendor/kyber_dilithium/mlkem",
    "vendor/kyber_dilithium/mldsa",
]

# Collect all .c files from mlkem and mldsa
import glob
mlkem_sources = glob.glob("vendor/kyber_dilithium/mlkem/*.c")
mlkem_sources = [
    fname for fname in glob.glob("vendor/kyber_dilithium/mlkem/*.c")
    if not fname.endswith("fips202.c")
]
mldsa_sources = [
    fname for fname in glob.glob("vendor/kyber_dilithium/mldsa/*.c")
    if not fname.endswith("fips202.c")
]
# Add fips202.c only once from HQC lib
common_sources = [os.path.join("vendor", "hqc", "lib", "fips202", "fips202.c")]

kyber_dilithium_extension = Extension(
    "_kyber_dilithium",
    sources=[
        "vendor/kyber_dilithium/kyber_dilithium_bindings.cpp",
    ] + mlkem_sources + mldsa_sources + common_sources,
    include_dirs=kyber_dilithium_include_dirs,
    language="c++",
    extra_compile_args=["-std=c++20"],
)


class BuildExt(_build_ext):
    def build_extension(self, ext):
        compiler_type = getattr(self.compiler, "compiler_type", "")
        args = list(getattr(ext, "extra_compile_args", []) or [])
        if compiler_type == "msvc":
            args = [arg for arg in args if not arg.startswith("-std")]
            if not any(arg.startswith("/std:") for arg in args):
                args.append("/std:c++20")
            if "/utf-8" not in args:
                args.append("/utf-8")
        else:
            args = [arg for arg in args if not arg.startswith("/std")]
            if not any(arg.startswith("-std=") for arg in args):
                args.append("-std=c++20")
        ext.extra_compile_args = args
        super().build_extension(ext)


setup(ext_modules=[falcon_extension, kyber_dilithium_extension], cmdclass={"build_ext": BuildExt})
