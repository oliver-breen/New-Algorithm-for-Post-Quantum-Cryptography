from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

import pybind11

falcon_extension = Extension(
    "quantaweave._falcon",
    sources=[
        "quantaweave/_falcon_bindings.cpp",
        "vendor/hqc/lib/fips202/fips202.c",
    ],
    include_dirs=[
        pybind11.get_include(),
        "vendor/falcon/include",
        "vendor/hqc/lib/fips202",
    ],
    language="c++",
    extra_compile_args=["-std=c++20"],
    libraries=["gmp", "gmpxx"],
)


class BuildExt(build_ext):
    def build_extension(self, ext):
        if self.compiler is None:
            return super().build_extension(ext)

        c_sources = [src for src in ext.sources if src.endswith(".c")]
        cxx_sources = [src for src in ext.sources if not src.endswith(".c")]
        extra_args = list(ext.extra_compile_args or [])
        cxx_args = extra_args
        c_args = [arg for arg in extra_args if arg != "-std=c++20"]

        objects = []
        if c_sources:
            objects.extend(
                self.compiler.compile(
                    c_sources,
                    output_dir=self.build_temp,
                    macros=ext.define_macros,
                    include_dirs=ext.include_dirs,
                    debug=self.debug,
                    extra_postargs=c_args,
                    depends=ext.depends,
                )
            )

        if cxx_sources:
            objects.extend(
                self.compiler.compile(
                    cxx_sources,
                    output_dir=self.build_temp,
                    macros=ext.define_macros,
                    include_dirs=ext.include_dirs,
                    debug=self.debug,
                    extra_postargs=cxx_args,
                    depends=ext.depends,
                )
            )

        self.compiler.link_shared_object(
            objects,
            self.get_ext_fullpath(ext.name),
            libraries=ext.libraries,
            library_dirs=ext.library_dirs,
            runtime_library_dirs=ext.runtime_library_dirs,
            extra_postargs=ext.extra_link_args,
            export_symbols=self.get_export_symbols(ext),
            debug=self.debug,
        )

setup(
    ext_modules=[falcon_extension],
    cmdclass={"build_ext": BuildExt},
)
