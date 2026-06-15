// SPDX-License-Identifier: MIT
//
// sha2/otp.hpp — HOTP (RFC 4226) and TOTP (RFC 6238) one-time passwords.
//
// HOTP is an HMAC-based one-time password using a monotonically increasing
// counter; TOTP replaces that counter with a time step. Both are the basis of
// hardware tokens and authenticator apps, and the same challenge-response shape
// appears in UDS Security Access. This implementation uses HMAC-SHA256 as the
// underlying PRF (RFC 6238 permits SHA-256/512 in addition to SHA-1).

#ifndef SHA2_OTP_HPP
#define SHA2_OTP_HPP

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "sha2/hmac.hpp"
#include "sha2/sha256.hpp"

namespace sha2 {

// Dynamic truncation (RFC 4226 §5.3) of an HMAC into a `digits`-long decimal
// one-time password.
template <class Hash>
std::string hotp(const std::uint8_t* key, std::size_t key_len, std::uint64_t counter,
                 unsigned digits = 6) {
    if (digits < 1 || digits > 9) throw std::invalid_argument("HOTP: digits must be 1..9");

    std::uint8_t msg[8];
    for (int i = 7; i >= 0; --i) {
        msg[i] = static_cast<std::uint8_t>(counter & 0xff);
        counter >>= 8;
    }

    auto hs = Hmac<Hash>::mac(key, key_len, msg, sizeof(msg));

    // Offset is taken from the low nibble of the last byte of the MAC.
    std::size_t offset = hs[hs.size() - 1] & 0x0f;
    std::uint32_t bin = (static_cast<std::uint32_t>(hs[offset] & 0x7f) << 24) |
                        (static_cast<std::uint32_t>(hs[offset + 1]) << 16) |
                        (static_cast<std::uint32_t>(hs[offset + 2]) << 8) |
                        (static_cast<std::uint32_t>(hs[offset + 3]));

    std::uint32_t mod = 1;
    for (unsigned i = 0; i < digits; ++i) mod *= 10;
    std::uint32_t code = bin % mod;

    std::string out(digits, '0');
    for (int i = static_cast<int>(digits) - 1; i >= 0; --i) {
        out[i] = static_cast<char>('0' + code % 10);
        code /= 10;
    }
    return out;
}

// TOTP (RFC 6238): HOTP applied to the time step floor((now - T0) / step).
template <class Hash>
std::string totp(const std::uint8_t* key, std::size_t key_len, std::uint64_t unix_time,
                 unsigned digits = 6, std::uint64_t step_seconds = 30, std::uint64_t t0 = 0) {
    if (step_seconds == 0) throw std::invalid_argument("TOTP: step must be > 0");
    std::uint64_t counter = (unix_time - t0) / step_seconds;
    return hotp<Hash>(key, key_len, counter, digits);
}

}  // namespace sha2

#endif  // SHA2_OTP_HPP
