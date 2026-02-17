cmake_minimum_required(VERSION 3.10)
project(dilithium_ref C)

set(SOURCES
    ntt.c
    packing.c
    poly.c
    polyvec.c
    reduce.c
    rounding.c
    sign.c
    symmetric-shake.c
    randombytes.c
    fips202.c
)

add_library(dilithium_ref SHARED ${SOURCES})

# Export all symbols for ctypes
set_target_properties(dilithium_ref PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)

target_include_directories(dilithium_ref PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
