// SPDX-License-Identifier: MIT
//
// sha2/util.hpp — small helpers shared across the toolkit: hex encoding/parsing,
// constant-time comparison, and best-effort secure zeroing of buffers.

#ifndef SHA2_UTIL_HPP
#define SHA2_UTIL_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sha2 {

// Lower-case hex encoding of a byte range.
inline std::string to_hex(const std::uint8_t* data, std::size_t len) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = kDigits[data[i] >> 4];
        out[2 * i + 1] = kDigits[data[i] & 0x0f];
    }
    return out;
}

template <std::size_t N>
inline std::string to_hex(const std::array<std::uint8_t, N>& d) {
    return to_hex(d.data(), d.size());
}

inline std::string to_hex(const std::vector<std::uint8_t>& d) {
    return to_hex(d.data(), d.size());
}

// Parse a hex string into bytes. Returns std::nullopt on odd length or any
// non-hex character. Accepts both upper- and lower-case digits.
inline std::optional<std::vector<std::uint8_t>> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// Constant-time equality: the running time depends only on `len`, not on the
// contents or on the position of the first differing byte. Use this whenever
// comparing a MAC or tag against an expected value to avoid leaking the match
// length through a timing side channel.
inline bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                                std::size_t len) noexcept {
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < len; ++i) diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

// Overwrite a buffer with zeros in a way the optimiser may not elide. Used to
// scrub key material and intermediate HMAC pads from the stack.
inline void secure_zero(void* ptr, std::size_t len) noexcept {
    volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

}  // namespace sha2

#endif  // SHA2_UTIL_HPP
