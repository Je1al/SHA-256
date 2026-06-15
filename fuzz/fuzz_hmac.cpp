// SPDX-License-Identifier: MIT
//
// libFuzzer harness for HMAC-SHA256. It splits the fuzz input into a key and a
// message and checks two invariants:
//
//   1. Streaming HMAC equals one-shot HMAC.
//   2. verify() accepts the correct tag (full and truncated) and rejects a tag
//      with any single bit flipped — guarding the constant-time comparison and
//      the truncated-MAC path used by AUTOSAR SecOC.
//
// Build (Clang):
//   clang++ -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined \
//           -Iinclude fuzz/fuzz_hmac.cpp -o fuzz_hmac

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "sha2/hmac.hpp"

using sha2::HmacSha256;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // First byte selects the key length; the rest splits into key || message.
    std::size_t key_len = size ? data[0] % (size + 1) : 0;
    const std::uint8_t* base = size ? data + 1 : data;
    std::size_t body = size ? size - 1 : 0;
    if (key_len > body) key_len = body;

    const std::uint8_t* key = base;
    const std::uint8_t* msg = base + key_len;
    std::size_t msg_len = body - key_len;

    auto one_shot = HmacSha256::mac(key, key_len, msg, msg_len);

    HmacSha256 streamed(key, key_len);
    std::size_t split = msg_len ? msg[0] % (msg_len + 1) : 0;
    streamed.update(msg, split);
    streamed.update(msg + split, msg_len - split);
    if (streamed.digest() != one_shot) std::abort();

    if (!HmacSha256::verify(key, key_len, msg, msg_len, one_shot.data(), one_shot.size()))
        std::abort();
    if (!HmacSha256::verify(key, key_len, msg, msg_len, one_shot.data(), 16))
        std::abort();

    auto tampered = one_shot;
    tampered[size % tampered.size()] ^= 0x80;
    if (HmacSha256::verify(key, key_len, msg, msg_len, tampered.data(), tampered.size()))
        std::abort();

    return 0;
}
