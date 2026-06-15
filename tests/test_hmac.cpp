// SPDX-License-Identifier: MIT
//
// HMAC-SHA256 known-answer tests from RFC 4231 (test cases 1–7), plus a
// constant-time verification / truncated-tag check.

#include <string>
#include <vector>

#include "sha2/hmac.hpp"
#include "sha2/util.hpp"
#include "test_framework.hpp"

using namespace sha2;

static std::vector<std::uint8_t> rep(std::uint8_t byte, std::size_t n) {
    return std::vector<std::uint8_t>(n, byte);
}
static std::vector<std::uint8_t> B(std::string_view s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}
static std::vector<std::uint8_t> Hx(std::string_view hex) { return *from_hex(hex); }

static std::string mac_hex(const std::vector<std::uint8_t>& key,
                           const std::vector<std::uint8_t>& msg) {
    return to_hex(HmacSha256::mac(key.data(), key.size(), msg.data(), msg.size()));
}

TEST(HmacSha256, Rfc4231) {
    // Test Case 1 — 20-byte key of 0x0b
    CHECK_EQ(mac_hex(rep(0x0b, 20), B("Hi There")),
             std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    // Test Case 2 — short ASCII key
    CHECK_EQ(mac_hex(B("Jefe"), B("what do ya want for nothing?")),
             std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
    // Test Case 3 — 20-byte key of 0xaa, 50 bytes of 0xdd
    CHECK_EQ(mac_hex(rep(0xaa, 20), rep(0xdd, 50)),
             std::string("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));
    // Test Case 4 — incrementing 25-byte key, 50 bytes of 0xcd
    CHECK_EQ(mac_hex(Hx("0102030405060708090a0b0c0d0e0f10111213141516171819"), rep(0xcd, 50)),
             std::string("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));
    // Test Case 6 — 131-byte key (> block size), hashed first
    CHECK_EQ(mac_hex(rep(0xaa, 131),
                     B("Test Using Larger Than Block-Size Key - Hash Key First")),
             std::string("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    // Test Case 7 — 131-byte key and long message
    CHECK_EQ(mac_hex(rep(0xaa, 131),
                     B("This is a test using a larger than block-size key and a larger than "
                       "block-size data. The key needs to be hashed before being used by the "
                       "HMAC algorithm.")),
             std::string("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
}

TEST(HmacSha256, VerifyConstantTime) {
    auto key = B("secret-key");
    auto msg = B("authenticated message");
    auto tag = HmacSha256::mac(key.data(), key.size(), msg.data(), msg.size());

    CHECK(HmacSha256::verify(key.data(), key.size(), msg.data(), msg.size(), tag.data(),
                             tag.size()));

    // A flipped bit must fail verification.
    tag[0] ^= 0x01;
    CHECK(!HmacSha256::verify(key.data(), key.size(), msg.data(), msg.size(), tag.data(),
                              tag.size()));
    tag[0] ^= 0x01;

    // Truncated-tag verification (AUTOSAR SecOC style): the leading 16 bytes of
    // a correct MAC must still verify.
    CHECK(HmacSha256::verify(key.data(), key.size(), msg.data(), msg.size(), tag.data(), 16));
}

int main() { return RUN_ALL_TESTS(); }
