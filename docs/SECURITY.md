# Security notes

## Intended use

This is a **reference implementation** intended for learning, experimentation,
and as the SHA-2 building blocks for my other security projects. It prioritises
readability and standards traceability. For production systems use a vetted,
audited library (OpenSSL, BoringSSL, libsodium, mbedTLS, wolfSSL).

## Threat model and what *is* addressed

The realistic threats for a software hashing/MAC library on a general-purpose or
embedded core are timing side channels and incorrect verification logic. The
library addresses these:

- **No secret-dependent control flow in the hash.** The SHA-2 compression
  function performs the same arithmetic and memory accesses regardless of the
  input *value*; the only data-dependent quantity is the message *length*. There
  are no secret-indexed table lookups or secret-dependent branches, so the
  primitive does not leak input bytes through instruction-timing or cache-timing
  channels.
- **Constant-time tag comparison.** `HmacSha256::verify()` and
  `constant_time_equal()` compare a candidate MAC against the expected value with
  a running OR of byte differences — the time depends only on the length, never
  on where (or whether) the first mismatch occurs. This prevents the classic
  timing oracle that lets an attacker forge a MAC byte by byte.
- **Truncated-MAC verification done right.** `verify()` takes an explicit
  `tag_len`, so SecOC-style truncated MACs are checked over exactly the
  transmitted prefix, in constant time, without ad-hoc slicing at the call site.
- **Best-effort secret scrubbing.** HMAC key pads, intermediate digests, and KDF
  working buffers are overwritten via `secure_zero()` (a `volatile`-qualified
  write loop the optimiser is not permitted to drop) before going out of scope.

## What is **not** addressed (limitations)

- **Physical side channels.** No countermeasures against power analysis (SPA/DPA),
  electromagnetic emanation, or fault injection. On a hardware target requiring
  those, use a certified hardware security module / crypto accelerator.
- **`secure_zero` is best-effort.** It defeats common dead-store elimination but
  cannot guarantee secrets never reach a register spill slot, swap, or core dump.
- **No formal verification or third-party audit.** Correctness rests on the test
  vectors, the differential corpus, and fuzzing — strong evidence, but not proof.
- **`std::vector` allocations** in the KDFs are not locked/`mlock`ed and may be
  paged to disk by the OS.

## Algorithm-choice guidance

- **PBKDF2** is included for standards compatibility (RFC 8018). For *new*
  password-hashing designs prefer a memory-hard function (Argon2id, scrypt);
  PBKDF2's compute-only cost is comparatively cheap to attack on GPUs/ASICs.
- **HOTP/TOTP** here use HMAC-SHA256 (permitted by RFC 6238). Interop with a
  given authenticator app may require HMAC-SHA1, which is intentionally *not*
  part of the public API.
- SHA-224 offers no practical advantage over SHA-256 on 32-bit cores and is
  provided for completeness / interoperability.

## Reporting

This is a personal portfolio project, not a deployed service. If you spot a
correctness or security issue, please open an issue on the repository.
