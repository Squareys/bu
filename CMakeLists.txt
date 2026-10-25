# backu — deduplicated, compressed, authenticated-encrypted incremental backups
# as one small native binary. Linux x86-64, clang, no STL in our own code (see
# CLAUDE.md), no exceptions, no RTTI.
cmake_minimum_required(VERSION 3.20)
project(backu VERSION 0.1.0 LANGUAGES C CXX)

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
# compiled out: backu refuses CPUs without AES-NI, and every AES-NI CPU has
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

# libsodium: ONE file (AES-256-GCM over AES-NI/PCLMUL) plus a five-symbol shim.
add_library(bk_aesgcm OBJECT
    third_party/libsodium/aead_aes256gcm_aesni.c
    third_party/libsodium/shim/sodium_shim.c)
target_include_directories(bk_aesgcm PRIVATE third_party/libsodium/include/sodium)
target_compile_definitions(bk_aesgcm PRIVATE CONFIGURED=1 NATIVE_LITTLE_ENDIAN=1
    HAVE_TMMINTRIN_H=1 HAVE_WMMINTRIN_H=1 HAVE_GCC_MEMORY_FENCES=1 _GNU_SOURCE)
target_compile_options(bk_aesgcm PRIVATE -w ${BK_VENDOR_OPT} ${BK_COMMON_FLAGS} ${BK_LTO_FLAGS})

# ---------------------------------------------------------------- backu ----

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
    $<TARGET_OBJECTS:bk_lz4> $<TARGET_OBJECTS:bk_aesgcm>)

add_executable(backu src/main.cpp ${BK_OBJECTS})
target_include_directories(backu PRIVATE src)
target_compile_options(backu PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_COLD_OPT} ${BK_LTO_FLAGS})
target_link_options(backu PRIVATE ${BK_LINK_FLAGS} ${BK_NOSTDLIBXX})
target_compile_definitions(backu PRIVATE BACKU_VERSION="${PROJECT_VERSION}")
if(NOT BK_SANITIZE)
    # Strip at link time: the shipped artifact is the stripped one, and the
    # size budget is measured on exactly that file.
    target_link_options(backu PRIVATE -s)
endif()

# Unstripped twin for the size breakdown (scripts/size_report.sh).
if(NOT BK_SANITIZE)
    add_executable(backu_symbols src/main.cpp ${BK_OBJECTS})
    target_include_directories(backu_symbols PRIVATE src)
    target_compile_options(backu_symbols PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_COLD_OPT} ${BK_LTO_FLAGS})
    target_link_options(backu_symbols PRIVATE ${BK_LINK_FLAGS} ${BK_NOSTDLIBXX})
    target_compile_definitions(backu_symbols PRIVATE BACKU_VERSION="${PROJECT_VERSION}")
    set_target_properties(backu_symbols PROPERTIES EXCLUDE_FROM_ALL ON)
endif()

# ---------------------------------------------------------------- tests ----

enable_testing()
add_executable(backu_tests
    tests/test_main.cpp
    tests/test_crypto.cpp
    tests/test_codec.cpp
    tests/test_chunker.cpp
    tests/test_format.cpp
    ${BK_OBJECTS})
target_include_directories(backu_tests PRIVATE src tests)
target_compile_options(backu_tests PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_OPT_FLAGS} ${BK_LTO_FLAGS})
target_link_options(backu_tests PRIVATE ${BK_LINK_FLAGS})
add_test(NAME unit COMMAND backu_tests)

# Primitive throughput (scripts/bench.sh runs it); not part of the test gate.
add_executable(backu_bench tests/bench.cpp ${BK_OBJECTS})
target_include_directories(backu_bench PRIVATE src)
target_compile_options(backu_bench PRIVATE ${BK_CXX_FLAGS} ${BK_COMMON_FLAGS} ${BK_OPT_FLAGS} ${BK_LTO_FLAGS})
target_link_options(backu_bench PRIVATE ${BK_LINK_FLAGS})
