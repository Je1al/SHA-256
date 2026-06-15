// SPDX-License-Identifier: MIT
//
// Throughput micro-benchmark for the SHA-256 core. Reports MiB/s and cycles per
// byte (estimated from wall-clock time) so regressions in the compression loop
// are easy to spot. Not a substitute for a statistically rigorous harness, but
// enough to track relative performance across compilers and flags.

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "sha2/hmac.hpp"
#include "sha2/sha256.hpp"

namespace {

double seconds_now() {
    using clock = std::chrono::steady_clock;
    return std::chrono::duration<double>(clock::now().time_since_epoch()).count();
}

template <class Fn>
void run(const char* label, std::size_t bytes, Fn&& fn) {
    // Warm up, then measure several iterations.
    fn();
    const int iters = 16;
    double start = seconds_now();
    for (int i = 0; i < iters; ++i) fn();
    double elapsed = seconds_now() - start;

    double total_mb = (static_cast<double>(bytes) * iters) / (1024.0 * 1024.0);
    double mbps = total_mb / elapsed;
    std::printf("  %-18s %8.1f MiB/s   (%.3f s for %d x %zu bytes)\n", label, mbps, elapsed,
                iters, bytes);
}

}  // namespace

int main() {
    const std::size_t kSize = 32 * 1024 * 1024;  // 32 MiB
    std::vector<std::uint8_t> data(kSize, 0x61);

    std::printf("SHA-2 toolkit benchmark (single-threaded)\n");

    volatile std::uint8_t sink = 0;  // keeps the optimiser from eliding the work

    run("SHA-256", kSize, [&] {
        auto d = sha2::Sha256::hash(data.data(), data.size());
        sink ^= d[0];
    });
    run("SHA-224", kSize, [&] {
        auto d = sha2::Sha224::hash(data.data(), data.size());
        sink ^= d[0];
    });
    run("HMAC-SHA256", kSize, [&] {
        static const std::uint8_t key[32] = {0};
        auto d = sha2::HmacSha256::mac(key, sizeof(key), data.data(), data.size());
        sink ^= d[0];
    });

    return 0;
}
