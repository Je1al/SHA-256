// SPDX-License-Identifier: MIT
//
// A deliberately tiny single-header test harness: no dependencies, so the test
// suite builds with nothing but a C++17 compiler. Each TEST registers itself
// and is run by RUN_ALL_TESTS(); failures are reported with file:line context
// and the process exits non-zero so CI fails loudly.

#ifndef SHA2_TEST_FRAMEWORK_HPP
#define SHA2_TEST_FRAMEWORK_HPP

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace testing {

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

struct Failure {
    std::string message;
};

inline int& failure_count() {
    static int n = 0;
    return n;
}

inline void report_failure(const char* file, int line, const std::string& what) {
    ++failure_count();
    std::fprintf(stderr, "    FAIL %s:%d: %s\n", file, line, what.c_str());
}

inline int run_all() {
    int passed = 0, failed = 0;
    for (auto& tc : registry()) {
        int before = failure_count();
        try {
            tc.fn();
        } catch (const std::exception& e) {
            report_failure(__FILE__, __LINE__, std::string("unexpected exception: ") + e.what());
        }
        bool ok = failure_count() == before;
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", tc.name.c_str());
        ok ? ++passed : ++failed;
    }
    std::printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}

}  // namespace testing

#define TEST(suite, name)                                                            \
    static void suite##_##name##_impl();                                             \
    static ::testing::Registrar suite##_##name##_reg(#suite "." #name,               \
                                                     suite##_##name##_impl);         \
    static void suite##_##name##_impl()

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) ::testing::report_failure(__FILE__, __LINE__, "CHECK(" #cond ")"); \
    } while (0)

#define CHECK_EQ(a, b)                                                               \
    do {                                                                             \
        auto _va = (a);                                                              \
        auto _vb = (b);                                                              \
        if (!(_va == _vb))                                                           \
            ::testing::report_failure(__FILE__, __LINE__,                            \
                                      std::string("CHECK_EQ(" #a ", " #b ")\n        got: ") + \
                                          to_string_(_va) + "\n        want: " + to_string_(_vb)); \
    } while (0)

namespace testing {
inline std::string to_string_(const std::string& s) { return s; }
inline std::string to_string_(std::uint64_t v) { return std::to_string(v); }
inline std::string to_string_(int v) { return std::to_string(v); }
inline std::string to_string_(bool v) { return v ? "true" : "false"; }
}  // namespace testing
using testing::to_string_;

#define RUN_ALL_TESTS() ::testing::run_all()

#endif  // SHA2_TEST_FRAMEWORK_HPP
