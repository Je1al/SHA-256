// SPDX-License-Identifier: MIT
//
// SHA-256 / SHA-224 known-answer and property tests.
// Reference digests are the published examples from FIPS PUB 180-4 plus the
// well-known empty-string and one-million-'a' vectors.

#include <cstdint>
#include <string>
#include <vector>

#include "sha2/sha256.hpp"
#include "sha2/util.hpp"
#include "test_framework.hpp"

using namespace sha2;

static std::string sha256_hex(const std::string& msg) {
    return to_hex(Sha256::hash(msg));
}
static std::string sha224_hex(const std::string& msg) {
    return to_hex(Sha224::hash(msg));
}

TEST(Sha256, FipsExamples) {
    CHECK_EQ(sha256_hex(""),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256_hex("abc"),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
             std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

TEST(Sha256, MillionA) {
    std::string m(1000000, 'a');
    CHECK_EQ(sha256_hex(m),
             std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

TEST(Sha224, FipsExamples) {
    CHECK_EQ(sha224_hex(""),
             std::string("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"));
    CHECK_EQ(sha224_hex("abc"),
             std::string("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"));
    CHECK_EQ(sha224_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
             std::string("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"));
}

// The digest must not depend on how the message is split across update() calls.
TEST(Sha256, StreamingInvariance) {
    std::string msg;
    for (int i = 0; i < 1000; ++i) msg.push_back(static_cast<char>(i * 37 + 11));

    auto one_shot = to_hex(Sha256::hash(msg));

    for (std::size_t chunk : {std::size_t(1), std::size_t(7), std::size_t(63),
                              std::size_t(64), std::size_t(65), std::size_t(127)}) {
        Sha256 h;
        for (std::size_t off = 0; off < msg.size(); off += chunk) {
            std::size_t n = std::min(chunk, msg.size() - off);
            h.update(reinterpret_cast<const std::uint8_t*>(msg.data() + off), n);
        }
        CHECK_EQ(to_hex(h.digest()), one_shot);
    }
}

// A finalized instance must be reusable for a fresh message.
TEST(Sha256, ReusableAfterFinalize) {
    Sha256 h;
    h.update("abc");
    (void)h.digest();
    h.update("abc");
    CHECK_EQ(to_hex(h.digest()),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

// Exercise the padding boundary: messages around one block where the length
// field does or does not fit in the final block.
TEST(Sha256, PaddingBoundaries) {
    // Independently confirmed digests for 55, 56, 63 and 64 'a' bytes.
    struct Case { int n; const char* hex; };
    const Case cases[] = {
        {55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
        {56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
        {63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"},
        {64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
    };
    for (auto& c : cases) {
        std::string m(c.n, 'a');
        CHECK_EQ(sha256_hex(m), std::string(c.hex));
    }
}

int main() { return RUN_ALL_TESTS(); }
