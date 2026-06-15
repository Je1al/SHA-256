// SPDX-License-Identifier: MIT
//
// One-time-password tests:
//   * TOTP-SHA256 against the RFC 6238 Appendix B reference table.
//   * HOTP-SHA1 against the RFC 4226 Appendix D table (validates the dynamic
//     truncation logic against the original HOTP specification).

#include <string>
#include <vector>

#include "sha2/otp.hpp"
#include "sha2/sha256.hpp"
#include "test_framework.hpp"

// SHA-1 is implemented locally *only* for the RFC 4226 HOTP test vectors, which
// predate SHA-2. It is not part of the public library surface.
namespace {
struct Sha1 {
    static constexpr std::size_t kBlockSize = 64;
    static constexpr std::size_t kDigestSize = 20;
    using Digest = std::array<std::uint8_t, kDigestSize>;

    std::uint32_t s[5];
    std::uint64_t bitlen = 0;
    std::uint8_t buf[64];
    std::size_t buflen = 0;

    Sha1() { reset(); }
    void reset() {
        s[0] = 0x67452301; s[1] = 0xEFCDAB89; s[2] = 0x98BADCFE;
        s[3] = 0x10325476; s[4] = 0xC3D2E1F0; bitlen = 0; buflen = 0;
    }
    static std::uint32_t rol(std::uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }
    void block(const std::uint8_t* p) {
        std::uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (p[i * 4] << 24) | (p[i * 4 + 1] << 16) | (p[i * 4 + 2] << 8) | p[i * 4 + 3];
        for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        std::uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
        for (int i = 0; i < 80; ++i) {
            std::uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            std::uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e;
    }
    void update(const std::uint8_t* data, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i) {
            buf[buflen++] = data[i];
            if (buflen == 64) { block(buf); bitlen += 512; buflen = 0; }
        }
    }
    void update(std::string_view v) {
        update(reinterpret_cast<const std::uint8_t*>(v.data()), v.size());
    }
    void finalize(std::uint8_t* out) {
        bitlen += static_cast<std::uint64_t>(buflen) * 8;
        buf[buflen++] = 0x80;
        if (buflen > 56) { while (buflen < 64) buf[buflen++] = 0; block(buf); buflen = 0; }
        while (buflen < 56) buf[buflen++] = 0;
        for (int i = 7; i >= 0; --i) buf[buflen++] = static_cast<std::uint8_t>(bitlen >> (i * 8));
        block(buf);
        for (int i = 0; i < 20; ++i) out[i] = static_cast<std::uint8_t>(s[i / 4] >> (24 - 8 * (i % 4)));
        reset();
    }
    Digest digest() { Digest d{}; finalize(d.data()); return d; }
};
}  // namespace

using namespace sha2;

TEST(Totp, Rfc6238Sha256) {
    // RFC 6238 Appendix B uses an 8-digit code, 30-second step, and a 32-byte
    // ASCII key for the SHA-256 column.
    const std::string key = "12345678901234567890123456789012";
    const auto* k = reinterpret_cast<const std::uint8_t*>(key.data());

    struct Case { std::uint64_t t; const char* code; };
    const Case cases[] = {
        {59, "46119246"},          {1111111109, "68084774"}, {1111111111, "67062674"},
        {1234567890, "91819424"},  {2000000000, "90698825"}, {20000000000ULL, "77737706"},
    };
    for (auto& c : cases)
        CHECK_EQ(totp<Sha256>(k, key.size(), c.t, 8, 30, 0), std::string(c.code));
}

TEST(Hotp, Rfc4226Sha1) {
    const std::string key = "12345678901234567890";  // 20-byte ASCII secret
    const auto* k = reinterpret_cast<const std::uint8_t*>(key.data());

    const char* expected[] = {"755224", "287082", "359152", "969429", "338314",
                              "254676", "287922", "162583", "399871", "520489"};
    for (std::uint64_t counter = 0; counter < 10; ++counter)
        CHECK_EQ(hotp<Sha1>(k, key.size(), counter, 6), std::string(expected[counter]));
}

int main() { return RUN_ALL_TESTS(); }
