// SPDX-License-Identifier: MIT
//
// sha2/hmac.hpp — HMAC keyed-hash message authentication (RFC 2104, FIPS 198-1).
//
// Parameterised on any hash type from this library that exposes the usual
// kBlockSize / kDigestSize / Digest / streaming interface, so the same code
// yields HMAC-SHA256 and HMAC-SHA224. HMAC-SHA256 is the MAC mandated by
// AUTOSAR SecOC and is widely used for UDS Security Access and secure boot.

#ifndef SHA2_HMAC_HPP
#define SHA2_HMAC_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "sha2/sha256.hpp"
#include "sha2/util.hpp"

namespace sha2 {

template <class Hash>
class Hmac {
  public:
    static constexpr std::size_t kBlockSize = Hash::kBlockSize;
    static constexpr std::size_t kDigestSize = Hash::kDigestSize;
    using Digest = std::array<std::uint8_t, kDigestSize>;

    Hmac(const std::uint8_t* key, std::size_t key_len) noexcept { init(key, key_len); }
    explicit Hmac(std::string_view key) noexcept {
        init(reinterpret_cast<const std::uint8_t*>(key.data()), key.size());
    }
    ~Hmac() {
        secure_zero(o_key_pad_, sizeof(o_key_pad_));
    }

    Hmac& update(const std::uint8_t* data, std::size_t len) noexcept {
        inner_.update(data, len);
        return *this;
    }
    Hmac& update(std::string_view data) noexcept {
        inner_.update(data);
        return *this;
    }

    void finalize(std::uint8_t* out) noexcept {
        std::uint8_t inner_digest[kDigestSize];
        inner_.finalize(inner_digest);

        Hash outer;
        outer.update(o_key_pad_, kBlockSize);
        outer.update(inner_digest, kDigestSize);
        outer.finalize(out);

        secure_zero(inner_digest, sizeof(inner_digest));
    }

    Digest digest() noexcept {
        Digest d{};
        finalize(d.data());
        return d;
    }

    // One-shot HMAC over a single message.
    static Digest mac(const std::uint8_t* key, std::size_t key_len,
                      const std::uint8_t* data, std::size_t data_len) noexcept {
        Hmac h(key, key_len);
        h.update(data, data_len);
        return h.digest();
    }

    // Constant-time tag verification. `tag_len` may be shorter than the full
    // digest to support truncated MACs (e.g. AUTOSAR SecOC, which transmits
    // only the most significant bytes of the MAC).
    static bool verify(const std::uint8_t* key, std::size_t key_len,
                       const std::uint8_t* data, std::size_t data_len,
                       const std::uint8_t* tag, std::size_t tag_len) noexcept {
        if (tag_len > kDigestSize) return false;
        Digest expected = mac(key, key_len, data, data_len);
        return constant_time_equal(expected.data(), tag, tag_len);
    }

  private:
    void init(const std::uint8_t* key, std::size_t key_len) noexcept {
        std::uint8_t key_block[kBlockSize];
        secure_zero(key_block, sizeof(key_block));
        if (key_len > kBlockSize) {
            // Keys longer than the block size are replaced by their hash.
            Hash kh;
            kh.update(key, key_len);
            std::uint8_t hashed[kDigestSize];
            kh.finalize(hashed);
            for (std::size_t i = 0; i < kDigestSize; ++i) key_block[i] = hashed[i];
            secure_zero(hashed, sizeof(hashed));
        } else {
            for (std::size_t i = 0; i < key_len; ++i) key_block[i] = key[i];
        }

        std::uint8_t i_key_pad[kBlockSize];
        for (std::size_t i = 0; i < kBlockSize; ++i) {
            o_key_pad_[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x5c);
            i_key_pad[i] = static_cast<std::uint8_t>(key_block[i] ^ 0x36);
        }

        inner_.reset();
        inner_.update(i_key_pad, kBlockSize);

        secure_zero(key_block, sizeof(key_block));
        secure_zero(i_key_pad, sizeof(i_key_pad));
    }

    Hash inner_;
    std::uint8_t o_key_pad_[kBlockSize];
};

using HmacSha256 = Hmac<Sha256>;
using HmacSha224 = Hmac<Sha224>;

}  // namespace sha2

#endif  // SHA2_HMAC_HPP
