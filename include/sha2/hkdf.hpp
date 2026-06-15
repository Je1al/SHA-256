// SPDX-License-Identifier: MIT
//
// sha2/hkdf.hpp — HKDF, the HMAC-based Extract-and-Expand KDF (RFC 5869).
//
// HKDF turns input keying material of arbitrary quality (e.g. a raw ECDH shared
// secret) into one or more cryptographically strong, fixed-length keys. The
// two-stage Extract-then-Expand structure is the key schedule used by TLS 1.3,
// the Signal protocol, and automotive secure-channel designs.

#ifndef SHA2_HKDF_HPP
#define SHA2_HKDF_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "sha2/hmac.hpp"
#include "sha2/sha256.hpp"

namespace sha2 {

template <class Hash>
class Hkdf {
  public:
    using Hmac_ = Hmac<Hash>;
    static constexpr std::size_t kHashLen = Hash::kDigestSize;

    // HKDF-Extract: PRK = HMAC(salt, IKM). A missing/empty salt is replaced by
    // a string of HashLen zero bytes, per RFC 5869 §2.2.
    static typename Hmac_::Digest extract(const std::uint8_t* salt, std::size_t salt_len,
                                          const std::uint8_t* ikm, std::size_t ikm_len) {
        std::uint8_t zero_salt[kHashLen] = {0};
        if (salt == nullptr || salt_len == 0) {
            salt = zero_salt;
            salt_len = kHashLen;
        }
        return Hmac_::mac(salt, salt_len, ikm, ikm_len);
    }

    // HKDF-Expand: derive `length` bytes from a pseudorandom key (RFC 5869 §2.3).
    static std::vector<std::uint8_t> expand(const std::uint8_t* prk, std::size_t prk_len,
                                            const std::uint8_t* info, std::size_t info_len,
                                            std::size_t length) {
        if (length > 255 * kHashLen)
            throw std::length_error("HKDF-Expand: requested length exceeds 255*HashLen");

        std::vector<std::uint8_t> okm;
        okm.reserve(length);
        std::uint8_t t[kHashLen];
        std::size_t t_len = 0;

        for (std::uint8_t counter = 1; okm.size() < length; ++counter) {
            Hmac_ h(prk, prk_len);
            h.update(t, t_len);                 // T(0) is empty
            h.update(info, info_len);
            h.update(&counter, 1);
            h.finalize(t);
            t_len = kHashLen;
            std::size_t take = std::min(length - okm.size(), kHashLen);
            okm.insert(okm.end(), t, t + take);
        }
        secure_zero(t, sizeof(t));
        return okm;
    }

    // Convenience wrapper performing Extract followed by Expand.
    static std::vector<std::uint8_t> derive(const std::uint8_t* salt, std::size_t salt_len,
                                            const std::uint8_t* ikm, std::size_t ikm_len,
                                            const std::uint8_t* info, std::size_t info_len,
                                            std::size_t length) {
        auto prk = extract(salt, salt_len, ikm, ikm_len);
        auto okm = expand(prk.data(), prk.size(), info, info_len, length);
        secure_zero(prk.data(), prk.size());
        return okm;
    }
};

using HkdfSha256 = Hkdf<Sha256>;
using HkdfSha224 = Hkdf<Sha224>;

}  // namespace sha2

#endif  // SHA2_HKDF_HPP
