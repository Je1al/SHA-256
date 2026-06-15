// SPDX-License-Identifier: MIT
//
// PBKDF2-HMAC-SHA256 known-answer tests. Reference values cross-checked against
// RFC 7914 §11 and OpenSSL.

#include <string>
#include <vector>

#include "sha2/pbkdf2.hpp"
#include "sha2/util.hpp"
#include "test_framework.hpp"

using namespace sha2;

static std::string pbkdf2_hex(std::string_view password, std::string_view salt,
                              std::uint32_t iters, std::size_t dk_len) {
    auto dk = Pbkdf2HmacSha256::derive(
        reinterpret_cast<const std::uint8_t*>(password.data()), password.size(),
        reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(), iters, dk_len);
    return to_hex(dk);
}

TEST(Pbkdf2HmacSha256, KnownAnswers) {
    CHECK_EQ(pbkdf2_hex("password", "salt", 1, 32),
             std::string("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
    CHECK_EQ(pbkdf2_hex("password", "salt", 2, 32),
             std::string("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"));
    CHECK_EQ(pbkdf2_hex("password", "salt", 4096, 32),
             std::string("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
}

// RFC 7914 §11 — multi-block output (40 bytes) with long password and salt.
TEST(Pbkdf2HmacSha256, Rfc7914MultiBlock) {
    CHECK_EQ(pbkdf2_hex("passwordPASSWORDpassword",
                        "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40),
             std::string("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"
                         "c635518c7dac47e9"));
}

int main() { return RUN_ALL_TESTS(); }
