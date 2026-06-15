# Design notes

This document explains how the toolkit is built and why, for readers who want to
audit the code rather than just link against it.

## SHA-256 / SHA-224 (`sha2/sha256.hpp`)

SHA-256 processes the message in 512-bit blocks through 64 rounds of a
compression function operating on eight 32-bit working variables. The
implementation follows FIPS PUB 180-4 directly:

- **Constants.** `kRoundConstants[64]` are the first 32 bits of the fractional
  parts of the cube roots of the first 64 primes; the SHA-256 and SHA-224 initial
  hash values are stored in their respective traits structs.
- **Logical functions** (`Ch`, `Maj`, `Σ0`, `Σ1`, `σ0`, `σ1`) are `constexpr`
  free functions rather than macros, so they are typed, debuggable, and usable in
  constant expressions.
- **Message schedule.** The 64-word schedule `W` is expanded on the stack per
  block; the compression updates the working variables and folds them back into
  the running state.

### One core, two digests

SHA-224 is SHA-256 with a different initial hash value and the output truncated
to the leftmost 224 bits. Rather than duplicate the compression function, the
engine is a class template `HashFunction<Traits>` parameterised on a traits
struct that supplies the initial state and digest length:

```cpp
using Sha256 = detail::HashFunction<detail::Sha256Traits>;
using Sha224 = detail::HashFunction<detail::Sha224Traits>;
```

This guarantees the two variants can never drift apart and keeps the audited
surface area minimal.

### Streaming API

`reset()` / `update()` / `finalize()` allow hashing arbitrarily large or
chunked input with O(1) memory. `update()` buffers partial blocks; `finalize()`
appends the `0x80` byte, zero padding, and the 64-bit big-endian bit length,
then resets the instance so it can be reused. The result is independent of how
the input is split — a property exercised directly by the test suite and the
fuzzer.

## HMAC (`sha2/hmac.hpp`)

`Hmac<Hash>` implements RFC 2104: `H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m))`. Keys
longer than the block size are hashed first; shorter keys are zero-padded. The
inner hash is updated incrementally so HMAC inherits the streaming API. Pads and
intermediate digests are wiped with `secure_zero` on destruction.

`verify()` recomputes the MAC and compares it to the supplied tag in **constant
time**, and accepts a `tag_len` shorter than the digest to support truncated
MACs (AUTOSAR SecOC transmits only the most-significant bytes).

## HKDF (`sha2/hkdf.hpp`)

A textbook RFC 5869 Extract-then-Expand:

- `extract(salt, ikm) → PRK = HMAC(salt, ikm)`, substituting a zero salt of
  `HashLen` bytes when none is given.
- `expand(PRK, info, L)` iterates `T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)` and
  concatenates until `L` bytes are produced, rejecting `L > 255·HashLen`.

## PBKDF2 (`sha2/pbkdf2.hpp`)

RFC 8018 PBKDF2 with HMAC-SHA256 as the PRF. For each output block it computes
`U1 = PRF(P, S ‖ INT_BE(i))` and folds `U2…Uc` in by XOR. Deliberately serial
and iteration-bound: the cost parameter is the security parameter.

## One-time passwords (`sha2/otp.hpp`)

`hotp<Hash>()` implements the RFC 4226 dynamic-truncation step — take the low
nibble of the last MAC byte as an offset, read a 31-bit big-endian integer from
there, and reduce modulo `10^digits`. `totp<Hash>()` is HOTP applied to the time
step `⌊(now − T0) / step⌋` (RFC 6238). The library uses HMAC-SHA256 as the PRF;
the HOTP-SHA1 path exists only inside the test to validate truncation against the
original RFC 4226 vectors.

## Testing strategy

Three complementary layers (see also [testing rationale in the README](../README.md#standards-compliance--test-vectors)):

1. **Named standard vectors** — FIPS 180-4, RFC 4231/5869/7914/6238/4226 — give
   specification traceability.
2. **A generated differential corpus** (`tests/vectors/generate_kat.py`) hashes
   ~145 messages of every length around the padding boundaries against a
   reference implementation, then commits the answers as a header so CI needs no
   runtime crypto dependency. CI re-runs the generator and diffs the output to
   prove the corpus is reproducible.
3. **Property-based fuzzing** asserts invariants that must hold for *all* inputs.

All tests and fuzzers run under AddressSanitizer + UndefinedBehaviorSanitizer in
CI across GCC and Clang on Linux and macOS.
