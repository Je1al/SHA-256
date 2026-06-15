// SPDX-License-Identifier: MIT
//
// sha2/sha256.hpp — SHA-224 / SHA-256 (FIPS PUB 180-4).
//
// A from-scratch, dependency-free, header-only implementation of the SHA-2
// 32-bit family. The two digest lengths share a single compression core and
// differ only in their initial hash value and final truncation, so they are
// expressed as a class template parameterised on a small traits struct.
//
// Design goals:
//   * Correctness first — validated against the FIPS 180-4 examples and the
//     NIST CAVP byte-oriented test vectors (see tests/).
//   * No secret-dependent branches or table indexing: the control flow depends
//     only on the *length* of the input, never on its value, which keeps the
//     primitive free of input-dependent timing side channels.
//   * Streaming (init/update/finalize) and one-shot APIs, suitable for hashing
//     data that does not fit in memory (firmware images, CAN log captures, …).

#ifndef SHA2_SHA256_HPP
#define SHA2_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace sha2 {
namespace detail {

// Round constants K_t (FIPS 180-4 §4.2.2): the first 32 bits of the fractional
// parts of the cube roots of the first 64 prime numbers.
inline constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

// Traits selecting the SHA-256 variant (full 256-bit digest).
struct Sha256Traits {
    static constexpr std::size_t kDigestSize = 32;
    static constexpr std::uint32_t kInitState[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
};

// Traits selecting the SHA-224 variant: same compression, different IV, output
// truncated to the leftmost 224 bits.
struct Sha224Traits {
    static constexpr std::size_t kDigestSize = 28;
    static constexpr std::uint32_t kInitState[8] = {
        0xc1059ed8u, 0x367cd507u, 0x3070dd17u, 0xf70e5939u,
        0xffc00b31u, 0x68581511u, 0x64f98fa7u, 0xbefa4fa4u};
};

constexpr std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32 - n));
}
constexpr std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (~x & z);
}
constexpr std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}
constexpr std::uint32_t bsig0(std::uint32_t x) noexcept {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
constexpr std::uint32_t bsig1(std::uint32_t x) noexcept {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
constexpr std::uint32_t ssig0(std::uint32_t x) noexcept {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
constexpr std::uint32_t ssig1(std::uint32_t x) noexcept {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

template <class Traits>
class HashFunction {
  public:
    static constexpr std::size_t kBlockSize = 64;   // 512-bit message block
    static constexpr std::size_t kDigestSize = Traits::kDigestSize;
    using Digest = std::array<std::uint8_t, kDigestSize>;

    HashFunction() noexcept { reset(); }

    // Return the object to its initial state, ready to hash a fresh message.
    void reset() noexcept {
        for (std::size_t i = 0; i < 8; ++i) state_[i] = Traits::kInitState[i];
        bitlen_ = 0;
        buflen_ = 0;
    }

    // Absorb `len` bytes of message. May be called repeatedly; the running
    // result is identical regardless of how the input is chunked.
    HashFunction& update(const std::uint8_t* data, std::size_t len) noexcept {
        for (std::size_t i = 0; i < len; ++i) {
            buffer_[buflen_++] = data[i];
            if (buflen_ == kBlockSize) {
                compress(buffer_);
                bitlen_ += 512;
                buflen_ = 0;
            }
        }
        return *this;
    }

    HashFunction& update(std::string_view data) noexcept {
        return update(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    }

    // Apply padding, emit the digest into `out` (kDigestSize bytes), then reset
    // so the instance can be reused.
    void finalize(std::uint8_t* out) noexcept {
        bitlen_ += static_cast<std::uint64_t>(buflen_) * 8;

        buffer_[buflen_++] = 0x80;  // the single '1' padding bit
        if (buflen_ > 56) {
            while (buflen_ < kBlockSize) buffer_[buflen_++] = 0;
            compress(buffer_);
            buflen_ = 0;
        }
        while (buflen_ < 56) buffer_[buflen_++] = 0;

        // Append the 64-bit big-endian message length in bits.
        for (int i = 7; i >= 0; --i)
            buffer_[buflen_++] = static_cast<std::uint8_t>(bitlen_ >> (i * 8));
        compress(buffer_);

        // Serialise the state, big-endian, truncating for SHA-224.
        for (std::size_t i = 0; i < kDigestSize; ++i)
            out[i] = static_cast<std::uint8_t>(state_[i / 4] >> (24 - 8 * (i % 4)));

        reset();
    }

    Digest digest() noexcept {
        Digest d{};
        finalize(d.data());
        return d;
    }

    // One-shot convenience helpers.
    static Digest hash(const std::uint8_t* data, std::size_t len) noexcept {
        HashFunction h;
        h.update(data, len);
        return h.digest();
    }
    static Digest hash(std::string_view data) noexcept {
        return hash(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    }

  private:
    void compress(const std::uint8_t* block) noexcept {
        std::uint32_t w[64];
        for (int t = 0; t < 16; ++t)
            w[t] = (static_cast<std::uint32_t>(block[t * 4]) << 24) |
                   (static_cast<std::uint32_t>(block[t * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(block[t * 4 + 2]) << 8) |
                   (static_cast<std::uint32_t>(block[t * 4 + 3]));
        for (int t = 16; t < 64; ++t)
            w[t] = ssig1(w[t - 2]) + w[t - 7] + ssig0(w[t - 15]) + w[t - 16];

        std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

        for (int t = 0; t < 64; ++t) {
            std::uint32_t t1 = h + bsig1(e) + ch(e, f, g) + kRoundConstants[t] + w[t];
            std::uint32_t t2 = bsig0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }

    std::uint32_t state_[8];
    std::uint64_t bitlen_;
    std::uint8_t buffer_[kBlockSize];
    std::size_t buflen_;
};

}  // namespace detail

using Sha256 = detail::HashFunction<detail::Sha256Traits>;
using Sha224 = detail::HashFunction<detail::Sha224Traits>;

}  // namespace sha2

#endif  // SHA2_SHA256_HPP
