# bu — deduplicated, compressed, authenticated-encrypted incremental backups
# as one small native binary. Linux x86-64, clang, no STL in our own code (see
# CLAUDE.md), no exceptions, no RTTI.
cmake_minimum_required(VERSION 3.20)
project(bu VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
# Our flag lists below are the whole story; CMake's per-config defaults
# (-O3 -DNDEBUG for Release) would otherwise be prepended and fight them.
set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS_RELEASE "")
set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_CXX_FLAGS_DEBUG "")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(BK_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(BK_TSAN "Build with ThreadSanitizer (the create pipeline and the thread pool)" OFF)

# ---------------------------------------------------------------- flags ----
#
# THE SIZE RULE (CLAUDE.md): small by default, speed wins on hot paths. So the
# size work below is all of the kind that costs no speed — dead-code removal
# (sections + --gc-sections), whole-program LTO (which also inlines across the
# vendored libraries), no unwind tables (no exceptions means nothing unwinds),
# hidden visibility, a stripped binary — while every hot path keeps -O2/-O3 and
# every SIMD variant. -Os is NOT used anywhere: it would make LZ4 and BLAKE3
# measurably slower to save a few KB.
set(BK_COMMON_FLAGS
    -ffunction-sections -fdata-sections
    -fno-asynchronous-unwind-tables -fno-unwind-tables
    -fvisibility=hidden
    -fno-plt
)
set(BK_CXX_FLAGS
    -fno-exceptions -fno-rtti
    -fno-threadsafe-statics      # the one function-local static (the heap allocator) is set up before any thread
    -Wall -Wextra
    -Wno-unused-parameter
    -Werror=return-type
    -Werror=return-stack-address
    -Werror=uninitialized
    -Werror=sometimes-uninitialized
    -Werror=unused-result
    -Werror=format -Werror=format-security
    -Wimplicit-fallthrough -Werror=implicit-fallthrough
    -Werror=dangling
)

if(BK_SANITIZE AND BK_TSAN)
    message(FATAL_ERROR "BK_SANITIZE and BK_TSAN are separate builds")
endif()
if(BK_TSAN)
    set(BK_SANITIZE ON)    # same build shape (no LTO, -O1 -g), different sanitizer
    set(BK_SAN_KIND thread)
else()
    set(BK_SAN_KIND address,undefined)
endif()
if(BK_SANITIZE)
    set(BK_OPT_FLAGS -O1 -g -fno-omit-frame-pointer
        -fsanitize=${BK_SAN_KIND} -fno-sanitize-recover=all)
    set(BK_LINK_FLAGS -fsanitize=${BK_SAN_KIND})
    set(BK_LTO_FLAGS)
    set(BK_NOSTDLIBXX)              # the ASan runtime's C++ half needs libstdc++
else()
    # No STL, no exceptions, no RTTI: nothing needs libstdc++, so don't link it.
    set(BK_NOSTDLIBXX -nostdlib++)
    set(BK_OPT_FLAGS -O2 -DNDEBUG)
    set(BK_LTO_FLAGS -flto)
    # lld: --gc-sections drops every unreferenced function the sections flags
    # isolated, --icf=all folds identical ones, -O2 lets lld optimise the string
    # tables, and --build-id=none drops 36 bytes nobody here reads.
    set(BK_LINK_FLAGS -fuse-ld=lld -flto -Wl,--gc-sections -Wl,--icf=all -Wl,-O2
        -Wl,--as-needed -Wl,--hash-style=gnu -Wl,--build-id=none)
endif()

# ---------------------------------------------------------- third party ----
# Each vendored library is its own object library compiled with -w and its
# upstream defines; see third_party/README for versions and the one TU allowed
# to include each header.

set(BK_VENDOR_OPT -O3)
if(BK_SANITIZE)
    set(BK_VENDOR_OPT -O1 -g)
endif()

# BLAKE3: portable + SSE4.1 + AVX2 + AVX-512, runtime dispatch kept. SSE2 is
# compiled out: bu refuses CPUs without AES-NI, and every AES-NI CPU has
# SSE4.1, so the SSE2 variant could never be selected.
add_library(bk_blake3 OBJECT
    third_party/blake3/blake3.c
    third_party/blake3/blake3_dispatch.c
    third_party/blake3/blake3_portable.c
    third_party/blake3/blake3_sse41.c
    third_party/blake3/blake3_avx2.c
    third_party/blake3/blake3_avx512.c)
target_compile_definitions(bk_blake3 PRIVATE BLAKE3_NO_SSE2)
target_compile_options(bk_blake3 PRIVATE -w ${BK_VENDOR_OPT} ${BK_COMMON_FLAGS} ${BK_LTO_FLAGS})
set_source_files_properties(third_party/blake3/blake3_sse41.c PROPERTIES COMPILE_OPTIONS "-msse4.1")
set_source_files_properties(third_party/blake3/blake3_avx2.c PROPERTIES COMPILE_OPTIONS "-mavx2")
set_source_files_properties(third_party/blake3/blake3_avx512.c PROPERTIES COMPILE_OPTIONS "-mavx512f;-mavx512vl")

# LZ4 block format only (no frame, no HC).
add_library(bk_lz4 OBJECT third_party/lz4/lz4.c)
target_compile_options(bk_lz4 PRIVATE -w ${BK_VENDOR_OPT} ${BK_COMMON_FLAGS} ${BK_LTO_FLAGS})

# libsodium: AES-256-GCM over AES-NI/PCLMUL (one file), plus a small shim for
# the support symbols it and Argon2 reference (third_party/README).
add_library(bk_aesgcm OBJECT
    third_party/libsodium/aead_aes256gcm_aesni.c
    third_party/libsodium/shim/sodium_shim.c)
target_include_directories(bk_aesgcm PRIVATE third_party/libsodium/include/sodium)
target_compile_definitions(bk_aesgcm PRIVATE CONFIGURED=1 NATIVE_LITTLE_ENDIAN=1
    HAVE_TMMINTRIN_H=1 HAVE_WMMINTRIN_H=1 HAVE_GCC_MEMORY_FENCES=1 _GNU_SOURCE)
target_compile_options(bk_aesgcm PRIVATE -w ${BK_VENDOR_OPT} ${BK_COMMON_FLAGS} ${BK_LTO_FLAGS})

# libsodium: Argon2id (crypto_pwhash_argon2id) for the key file's passphrase
# slots. The fill-block kernels for SSSE3, AVX2 and AVX-512F carry their own
# target pragmas and are picked at run time from runtime.c's CPUID answers, as
# upstream does; the HAVE_* defines are what configure finds on x86-64 Linux.
# HAVE_MMAP: the (up to GiB-sized) Argon2 matrix is an anonymous mapping that
# munmap hands straight back to the kernel. codecs.c is there only because
# argon2.c's encoded-string API references its base64 functions; bu never
# calls that API and --gc-sections drops it.
add_library(bk_argon2 OBJECT
    third_party/libsodium/argon2/argon2.c
    third_party/libsodium/argon2/argon2-core.c
    third_party/libsodium/argon2/argon2-encoding.c
    third_party/libsodium/argon2/argon2-fill-block-ref.c
    third_party/libsodium/argon2/argon2-fill-block-ssse3.c
    third_party/libsodium/argon2/argon2-fill-block-avx2.c
    third_party/libsodium/argon2/argon2-fill-block-avx512f.c
    third_party/libsodium/argon2/blake2b-long.c
    third_party/libsodium/argon2/pwhash_argon2id.c
    third_party/libsodium/runtime.c
    third_party/libsodium/codecs.c)
target_include_directories(bk_argon2 PRIVATE third_party/libsodium/include/sodium)
target_compile_definitions(bk_argon2 PRIVATE CONFIGURED=1 NATIVE_LITTLE_ENDIAN=1
    HAVE_EMMINTRIN_H=1 HAVE_PMMINTRIN_H=1 HAVE_TMMINTRIN_H=1 HAVE_SMMINTRIN_H=1
    HAVE_AVXINTRIN_H=1 HAVE_AVX2INTRIN_H=1 HAVE_AVX512FINTRIN_H=1 HAVE_WMMINTRIN_H=1
    HAVE_CPUID=1 HAVE_AVX_ASM=1 HAVE_MMAP=1 HAVE_SYS_MMAN_H=1 _GNU_SOURCE)
target_compile_options(bk_argon2 PRIVATE -w ${BK_VENDOR_OPT} ${BK_COMMON_FLAGS} ${BK_LTO_FLAGS})

# libsodium: BLAKE2b, which Argon2 uses for its first and last block only, so
# the portable compression function is all it gets (no HAVE_* SIMD defines:
# blake2b_pick_best_implementation then references only the reference code).
add_library(bk_blake2b OBJECT
    third_party/libsodium/blake2b/blake2b-ref.c
    third_party/libsodium/blake2b/blake2b-compress-ref.c
    third_party/libsodium/blake2b/generichash_blake2b.c)
target_include_directories(bk_blake2b PRIVATE third_party/libsodium/include/sodium)
target_compile_definitions(bk_blake2b PRIVATE CONFIGURED=1 NATIVE_LITTLE_ENDIAN=1 _GNU_SOURCE)
target_compile_options(bk_blake2b PRIVATE -w ${BK_VENDOR_OPT} ${BK_COMMON_FLAGS} ${BK_LTO_FLAGS})

# ------------------------------------------------------------------- bu ----

# Hot: per-byte or per-chunk work. These keep -O2 (the vendored code -O3).
set(BK_HOT_SOURCES
    src/core/memory.cpp
    src/crypto/crypto.cpp
    src/format/codec.cpp
    src/chunk/chunker.cpp
)
# Cold: per-file or per-command work — argument parsing, the walk, manifest
# coding, the pipeline's bookkeeping (its per-chunk work is calls into the hot
# set). Built -Os: measured on this code it halves the size, and none of it is
# where a backup spends its time (docs/design.md §Size has the numbers). With
# LTO the optsize attribute travels with each function, so a cold caller does
# not drag a hot callee down to -Os, nor the other way round.
set(BK_COLD_SOURCES
    src/core/thread.cpp
    src/io/io.cpp
    src/format/container.cpp
    src/format/snapshot.cpp
    src/cmd/args.cpp
    src/cmd/chain.cpp
    src/cmd/create.cpp
    src/cmd/restore.cpp
    src/cmd/merge.cpp
    src/cmd/inspect.cpp
)
if(BK_SANITIZE)
    set(BK_COLD_OPT ${BK_OPT_FLAGS})
else()
    set(BK_COLD_OPT -Oz -DNDEBUG)
endif()

add_library(bk_hot OBJECT ${BK_HOT_SOURCES})
target_include_directories(bk_hot PUBLIC src)
target_include_directories(bk_hot PRIVATE third_party/blake3 third_party/lz4 third_party/libsodium/include)
target_compile_options(bk_hot PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_OPT_FLAGS} ${BK_LTO_FLAGS})

add_library(bk_cold OBJECT ${BK_COLD_SOURCES})
target_include_directories(bk_cold PUBLIC src)
target_compile_options(bk_cold PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_COLD_OPT} ${BK_LTO_FLAGS})

set(BK_OBJECTS $<TARGET_OBJECTS:bk_hot> $<TARGET_OBJECTS:bk_cold> $<TARGET_OBJECTS:bk_blake3>
    $<TARGET_OBJECTS:bk_lz4> $<TARGET_OBJECTS:bk_aesgcm> $<TARGET_OBJECTS:bk_argon2>
    $<TARGET_OBJECTS:bk_blake2b>)

add_executable(bu src/main.cpp ${BK_OBJECTS})
target_include_directories(bu PRIVATE src)
target_compile_options(bu PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_COLD_OPT} ${BK_LTO_FLAGS})
target_link_options(bu PRIVATE ${BK_LINK_FLAGS} ${BK_NOSTDLIBXX})
target_compile_definitions(bu PRIVATE BU_VERSION="${PROJECT_VERSION}")
if(NOT BK_SANITIZE)
    # Strip at link time: the shipped artifact is the stripped one, and the
    # size budget is measured on exactly that file.
    target_link_options(bu PRIVATE -s)
endif()

# Unstripped twin for the size breakdown (scripts/size_report.sh).
if(NOT BK_SANITIZE)
    add_executable(bu_symbols src/main.cpp ${BK_OBJECTS})
    target_include_directories(bu_symbols PRIVATE src)
    target_compile_options(bu_symbols PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_COLD_OPT} ${BK_LTO_FLAGS})
    target_link_options(bu_symbols PRIVATE ${BK_LINK_FLAGS} ${BK_NOSTDLIBXX})
    target_compile_definitions(bu_symbols PRIVATE BU_VERSION="${PROJECT_VERSION}")
    set_target_properties(bu_symbols PROPERTIES EXCLUDE_FROM_ALL ON)
endif()

# ---------------------------------------------------------------- tests ----

enable_testing()
add_executable(bu_tests
    tests/test_main.cpp
    tests/test_crypto.cpp
    tests/test_codec.cpp
    tests/test_chunker.cpp
    tests/test_format.cpp
    ${BK_OBJECTS})
target_include_directories(bu_tests PRIVATE src tests)
target_compile_options(bu_tests PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_OPT_FLAGS} ${BK_LTO_FLAGS})
target_link_options(bu_tests PRIVATE ${BK_LINK_FLAGS})
add_test(NAME unit COMMAND bu_tests)

# Primitive throughput (scripts/bench.sh runs it); not part of the test gate.
add_executable(bu_bench tests/bench.cpp ${BK_OBJECTS})
target_include_directories(bu_bench PRIVATE src)
target_compile_options(bu_bench PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_OPT_FLAGS} ${BK_LTO_FLAGS})
target_link_options(bu_bench PRIVATE ${BK_LINK_FLAGS})
