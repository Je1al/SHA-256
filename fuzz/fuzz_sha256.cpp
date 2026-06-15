// SPDX-License-Identifier: MIT
//
// libFuzzer harness for the SHA-256 streaming engine. Rather than assert a
// fixed digest, it checks structural invariants that must hold for *any* input,
// which is exactly the kind of property a coverage-guided fuzzer is good at
// breaking:
//
//   1. Chunking invariance — splitting the message at an arbitrary, input-
//      derived boundary must not change the digest.
//   2. One-shot vs streaming equivalence.
//   3. Reuse safety — an instance reset by finalize() produces the same result
//      as a fresh instance.
//
// Build (Clang):
//   clang++ -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined \
//           -Iinclude fuzz/fuzz_sha256.cpp -o fuzz_sha256

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "sha2/sha256.hpp"

using sha2::Sha256;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto one_shot = Sha256::hash(data, size);

    // Split point derived from the data so the fuzzer can explore boundaries.
    std::size_t split = size ? data[0] % (size + 1) : 0;

    Sha256 streamed;
    streamed.update(data, split);
    streamed.update(data + split, size - split);
    auto streamed_digest = streamed.digest();

    if (streamed_digest != one_shot) std::abort();

    // Byte-at-a-time must also agree.
    Sha256 byte_by_byte;
    for (std::size_t i = 0; i < size; ++i) byte_by_byte.update(data + i, 1);
    if (byte_by_byte.digest() != one_shot) std::abort();

    // Reuse after finalize() must match a fresh instance.
    Sha256 reused;
    reused.update(data, size);
    (void)reused.digest();
    reused.update(data, size);
    if (reused.digest() != one_shot) std::abort();

    return 0;
}
