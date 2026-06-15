// SPDX-License-Identifier: MIT
//
// sha2/pbkdf2.hpp — PBKDF2 password-based key derivation (RFC 8018 / PKCS #5).
//
// PBKDF2 stretches a low-entropy password into a derived key by iterating
// HMAC many times, deliberately raising the cost of brute-force guessing. This
// instantiation uses HMAC-SHA256 as the PRF.

#ifndef SHA2_PBKDF2_HPP
#define SHA2_PBKDF2_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "sha2/hmac.hpp"
#include "sha2/sha256.hpp"

namespace sha2 {

template <class Hash>
class Pbkdf2 {
  public:
    using Hmac_ = Hmac<Hash>;
    static constexpr std::size_t kHashLen = Hash::kDigestSize;

    static std::vector<std::uint8_t> derive(const std::uint8_t* password, std::size_t password_len,
                                            const std::uint8_t* salt, std::size_t salt_len,
                                            std::uint32_t iterations, std::size_t dk_len) {
        if (iterations == 0) throw std::invalid_argument("PBKDF2: iterations must be >= 1");

        std::vector<std::uint8_t> dk;
        dk.reserve(dk_len);

        std::uint8_t u[kHashLen];
        std::uint8_t t[kHashLen];

        for (std::uint32_t block = 1; dk.size() < dk_len; ++block) {
            // U1 = PRF(password, salt || INT_32_BE(block))
            std::uint8_t block_be[4] = {
                static_cast<std::uint8_t>(block >> 24), static_cast<std::uint8_t>(block >> 16),
                static_cast<std::uint8_t>(block >> 8), static_cast<std::uint8_t>(block)};
            {
                Hmac_ h(password, password_len);
                h.update(salt, salt_len);
                h.update(block_be, 4);
                h.finalize(u);
            }
            for (std::size_t i = 0; i < kHashLen; ++i) t[i] = u[i];

            // T = U1 ^ U2 ^ ... ^ Uc
            for (std::uint32_t i = 1; i < iterations; ++i) {
                u_assign_(u, Hmac_::mac(password, password_len, u, kHashLen));
                for (std::size_t j = 0; j < kHashLen; ++j) t[j] ^= u[j];
            }

            std::size_t take = std::min(dk_len - dk.size(), kHashLen);
            dk.insert(dk.end(), t, t + take);
        }

        secure_zero(u, sizeof(u));
        secure_zero(t, sizeof(t));
        return dk;
    }

  private:
    static void u_assign_(std::uint8_t* dst, const typename Hmac_::Digest& src) noexcept {
        for (std::size_t i = 0; i < kHashLen; ++i) dst[i] = src[i];
    }
};

using Pbkdf2HmacSha256 = Pbkdf2<Sha256>;
using Pbkdf2HmacSha224 = Pbkdf2<Sha224>;

}  // namespace sha2

#endif  // SHA2_PBKDF2_HPP
