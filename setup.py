from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext as _build_ext

import pybind11


falcon_extension = Extension(
    "quantaweave._falcon",
    sources=[
        "quantaweave/_falcon_bindings.cpp",
        "quantaweave/_fips202_wrapper.cpp",
    ],
    include_dirs=[
        pybind11.get_include(),
        pybind11.get_include(True),
        "vendor/falcon/include",
        "vendor/hqc/lib/fips202",
    ],
    language="c++",
    extra_compile_args=["-std=c++20"],
    libraries=["gmp", "gmpxx"],
)


class BuildExt(_build_ext):
    def build_extension(self, ext):
        compiler_type = getattr(self.compiler, "compiler_type", "")
        args = list(getattr(ext, "extra_compile_args", []) or [])
        if compiler_type == "msvc":
            args = [arg for arg in args if not arg.startswith("-std")]
            if not any(arg.startswith("/std:") for arg in args):
                args.append("/std:c++20")
        else:
            args = [arg for arg in args if not arg.startswith("/std")]
            if not any(arg.startswith("-std=") for arg in args):
                args.append("-std=c++20")
        ext.extra_compile_args = args
        super().build_extension(ext)


setup(ext_modules=[falcon_extension], cmdclass={"build_ext": BuildExt})
