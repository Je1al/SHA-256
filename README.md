# SHA-2 Toolkit

[![CI](https://github.com/Je1al/SHA-256/actions/workflows/ci.yml/badge.svg)](https://github.com/Je1al/SHA-256/actions/workflows/ci.yml)
[![Standard: FIPS 180-4](https://img.shields.io/badge/standard-FIPS%20180--4-blue)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Language: C++17](https://img.shields.io/badge/C%2B%2B-17-00599C)](https://en.cppreference.com/w/cpp/17)

A **dependency-free, header-only C++17 implementation of the SHA-2 (32-bit) family
and the primitives built on top of it** — written from scratch and validated
against the official NIST / IETF test vectors.

This started as a one-file educational SHA-256 and grew into a small, auditable
crypto library covering the hashing stack that underpins real embedded and
**automotive security** systems: message authentication (AUTOSAR SecOC), key
derivation, secure boot / firmware integrity, and challenge-response
authentication.

> **Scope & honesty.** This is a *reference* implementation built for clarity,
> correctness and constant-time comparison of secrets. It is not hardened
> against power/EM side channels and has not been independently audited — for
> production use a vetted library (OpenSSL, BoringSSL, libsodium). What it *does*
> offer is a clean, fully tested, standards-traceable codebase you can read end
> to end. See [docs/SECURITY.md](docs/SECURITY.md).

---

## Features

| Primitive | Standard | Header | Notes |
|-----------|----------|--------|-------|
| **SHA-256** | FIPS 180-4 | `sha2/sha256.hpp` | Streaming + one-shot API |
| **SHA-224** | FIPS 180-4 | `sha2/sha256.hpp` | Shares the SHA-256 core (template) |
| **HMAC-SHA256 / 224** | RFC 2104, FIPS 198-1 | `sha2/hmac.hpp` | Constant-time `verify()`, truncated-MAC support |
| **HKDF** | RFC 5869 | `sha2/hkdf.hpp` | Extract-and-Expand key derivation |
| **PBKDF2** | RFC 8018 (PKCS #5) | `sha2/pbkdf2.hpp` | Password stretching with HMAC-SHA256 PRF |
| **HOTP / TOTP** | RFC 4226 / 6238 | `sha2/otp.hpp` | One-time passwords / challenge-response |
| **Utilities** | — | `sha2/util.hpp` | Hex, constant-time compare, secure zeroing |

Everything is header-only and lives under the `sha2::` namespace. No external
dependencies — just a C++17 compiler.

## Standards compliance & test vectors

Every primitive is checked against published reference vectors, so behaviour is
traceable to a specification rather than to "it matched OpenSSL on my machine":

| Test | Source |
|------|--------|
| SHA-256 / SHA-224 examples | **FIPS 180-4** (`abc`, multi-block, 1,000,000 × `a`) |
| SHA-2 padding boundaries | inputs of 55/56/63/64 bytes (final-block length edge cases) |
| Broad differential corpus | ~145 messages of every length 0–134 + large inputs, cross-checked against a reference implementation |
| HMAC-SHA256 | **RFC 4231** test cases 1–7 |
| HKDF-SHA256 | **RFC 5869** Appendix A (A.1–A.3) |
| PBKDF2-HMAC-SHA256 | **RFC 7914** §11 + known answers |
| TOTP-SHA256 | **RFC 6238** Appendix B reference table |
| HOTP-SHA1 | **RFC 4226** Appendix D (validates dynamic truncation) |

In addition, two **libFuzzer** harnesses run under AddressSanitizer + UBSan in
CI, asserting structural invariants (chunking invariance, one-shot ≡ streaming,
reuse safety, MAC verify accept/reject).

## Quick start

```bash
git clone https://github.com/Je1al/SHA-256.git
cd SHA-256
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### Library usage

```cpp
#include "sha2/sha2.hpp"
#include <iostream>

int main() {
    // One-shot hashing
    auto d = sha2::Sha256::hash("abc");
    std::cout << sha2::to_hex(d) << "\n";
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

    // Streaming (for data that does not fit in memory)
    sha2::Sha256 h;
    h.update("firmware ");
    h.update("image");
    auto digest = h.digest();

    // HMAC with constant-time verification (AUTOSAR SecOC uses a truncated MAC)
    const std::uint8_t key[16] = { /* session key */ };
    auto tag = sha2::HmacSha256::mac(key, sizeof(key), digest.data(), digest.size());
    bool ok  = sha2::HmacSha256::verify(key, sizeof(key),
                                        digest.data(), digest.size(),
                                        tag.data(), /*truncated*/ 16);

    // Derive a session key from an ECDH shared secret (HKDF)
    auto okm = sha2::HkdfSha256::derive(salt, salt_len, shared, shared_len,
                                        info, info_len, /*bytes*/ 32);
}
```

### Command-line tool

The `sha2` CLI exercises every primitive and is output-compatible with GNU
`sha256sum`, so it slots straight into existing verification scripts:

```bash
# Hash a firmware image and verify it later
./build/sha2 sha256 firmware.bin > firmware.sha256
./build/sha2 check  firmware.sha256          # firmware.bin: OK

echo -n abc | ./build/sha2 sha256            # ba7816bf...  -
./build/sha2 hmac   --key topsecret msg.bin  # HMAC-SHA256
./build/sha2 pbkdf2 --pass hunter2 --salt s --iter 100000 --len 32
./build/sha2 totp   --key 12345678901234567890123456789012 --time 59 --digits 8
./build/sha2 selftest
```

## Why this matters for automotive / embedded security

SHA-256 and HMAC-SHA256 are not academic curiosities — they are the workhorses
of modern in-vehicle security:

- **AUTOSAR SecOC** authenticates safety-relevant CAN/CAN-FD frames with a
  *truncated* HMAC-SHA256 plus a freshness value. The `verify()` API here takes
  an explicit `tag_len` and compares in constant time, mirroring that design.
- **Secure boot / firmware integrity** relies on SHA-256 digests of flash
  images; the streaming API hashes images larger than RAM.
- **UDS Security Access (ISO 14229)** is an HMAC-style challenge-response, the
  same shape as HOTP.
- **Session-key derivation** from an ECDH/PSK secret is exactly HKDF.

This complements my [car-security-simulator](https://github.com/Je1al/car-security-simulator)
(CAN IDS / SecOC / UDS) and [SecureIoT-Protocol](https://github.com/Je1al/SecureIoT-Protocol)
(X25519 + ChaCha20-Poly1305 secure channel) projects by providing the SHA-2
building blocks they rely on.

## Project layout

```
include/sha2/      header-only library (sha256, hmac, hkdf, pbkdf2, otp, util)
tools/sha2.cpp     command-line front-end
tests/             known-answer + property tests (tiny built-in harness)
tests/vectors/     generated differential KAT corpus + its generator
fuzz/              libFuzzer harnesses (SHA-256, HMAC)
bench/             throughput micro-benchmark
docs/              DESIGN.md, SECURITY.md
```

## Performance

The compression core is a portable, branch-clean scalar implementation (no
SHA-NI / NEON intrinsics). On an Apple M-series core with Apple clang `-O3` it
sustains roughly **145 MiB/s** for SHA-256, SHA-224 and HMAC-SHA256 alike.
Run it yourself:

```bash
cmake --build build --target sha2_bench && ./build/sha2_bench
```

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md) — algorithm walkthrough and implementation decisions.
- [docs/SECURITY.md](docs/SECURITY.md) — threat model, side-channel posture, limitations.

## License

[MIT](LICENSE).
