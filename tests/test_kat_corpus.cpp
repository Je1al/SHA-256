// SPDX-License-Identifier: MIT
//
// Differential known-answer test: hashes ~145 messages of every length around
// the padding boundaries (plus larger inputs) and 40 HMAC cases, comparing each
// against digests produced by a reference implementation (Python hashlib/hmac).
// The corpus lives in the auto-generated header tests/vectors/sha256_kat.hpp.

#include <string>

#include "sha2/hmac.hpp"
#include "sha2/sha256.hpp"
#include "sha2/util.hpp"
#include "test_framework.hpp"
#include "vectors/sha256_kat.hpp"

using namespace sha2;

TEST(KatCorpus, Sha256AndSha224) {
    int checked = 0;
    for (const auto& v : kat::hash_vectors()) {
        CHECK_EQ(to_hex(Sha256::hash(v.msg.data(), v.msg.size())), std::string(v.sha256));
        CHECK_EQ(to_hex(Sha224::hash(v.msg.data(), v.msg.size())), std::string(v.sha224));
        ++checked;
    }
    CHECK(checked > 100);
}

TEST(KatCorpus, HmacSha256) {
    int checked = 0;
    for (const auto& v : kat::hmac_vectors()) {
        auto mac = HmacSha256::mac(v.key.data(), v.key.size(), v.msg.data(), v.msg.size());
        CHECK_EQ(to_hex(mac), std::string(v.mac));
        ++checked;
    }
    CHECK(checked > 30);
}

int main() { return RUN_ALL_TESTS(); }
