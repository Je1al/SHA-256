// SPDX-License-Identifier: MIT
//
// sha2 — a small command-line front-end exercising every primitive in the
// toolkit. The `sha256`/`sha224` subcommands are compatible with the GNU
// coreutils `sha256sum` output format ("<hex>  <name>") and support a `-c`
// check mode, so the tool is a drop-in for verifying firmware images and
// release artefacts.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "sha2/sha2.hpp"

namespace {

using sha2::from_hex;
using sha2::to_hex;

// ---- Small argv option parser -------------------------------------------------

struct Options {
    std::map<std::string, std::string> kv;
    std::vector<std::string> positional;
    bool has(const std::string& k) const { return kv.count(k) != 0; }
    std::string get(const std::string& k, const std::string& def = "") const {
        auto it = kv.find(k);
        return it == kv.end() ? def : it->second;
    }
};

Options parse(int argc, char** argv, int start) {
    Options o;
    for (int i = start; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("--", 0) == 0) {
            std::string key = a.substr(2);
            if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
                o.kv[key] = argv[++i];
            } else {
                o.kv[key] = "1";  // boolean flag
            }
        } else {
            o.positional.push_back(a);
        }
    }
    return o;
}

std::vector<std::uint8_t> read_stream(std::istream& in) {
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in),
                                     std::istreambuf_iterator<char>());
}

bool read_file(const std::string& path, std::vector<std::uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out = read_stream(f);
    return true;
}

std::vector<std::uint8_t> as_bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

// Resolve a key argument given either --key (UTF-8 text) or --key-hex.
bool resolve_keyish(const Options& o, const char* text_flag, const char* hex_flag,
                    std::vector<std::uint8_t>& out, std::string& err) {
    if (o.has(hex_flag)) {
        auto parsed = from_hex(o.get(hex_flag));
        if (!parsed) { err = std::string("invalid hex in --") + hex_flag; return false; }
        out = *parsed;
        return true;
    }
    if (o.has(text_flag)) { out = as_bytes(o.get(text_flag)); return true; }
    err = std::string("missing --") + text_flag + " or --" + hex_flag;
    return false;
}

// ---- Subcommands --------------------------------------------------------------

template <class Hash>
int cmd_hash(const Options& o) {
    auto digest_stream = [](std::istream& in) {
        Hash h;
        char buf[65536];
        while (in) {
            in.read(buf, sizeof(buf));
            h.update(reinterpret_cast<const std::uint8_t*>(buf),
                     static_cast<std::size_t>(in.gcount()));
        }
        return to_hex(h.digest());
    };

    if (o.positional.empty()) {
        std::cout << digest_stream(std::cin) << "  -\n";
        return 0;
    }
    int rc = 0;
    for (const auto& path : o.positional) {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            std::cerr << "sha2: " << path << ": cannot open\n";
            rc = 1;
            continue;
        }
        std::cout << digest_stream(f) << "  " << path << "\n";
    }
    return rc;
}

// Verify a coreutils-style checksum file: lines of "<hex>  <path>".
template <class Hash>
int cmd_check(const Options& o) {
    if (o.positional.empty()) {
        std::cerr << "sha2 check: expected a checksum file\n";
        return 2;
    }
    std::ifstream list(o.positional[0]);
    if (!list) {
        std::cerr << "sha2 check: cannot open " << o.positional[0] << "\n";
        return 2;
    }
    int failures = 0, count = 0;
    std::string line;
    while (std::getline(list, line)) {
        if (line.empty()) continue;
        std::size_t sep = line.find("  ");
        if (sep == std::string::npos) sep = line.find(" *");
        if (sep == std::string::npos) continue;
        std::string want = line.substr(0, sep);
        std::string path = line.substr(sep + 2);

        std::vector<std::uint8_t> data;
        if (!read_file(path, data)) {
            std::cout << path << ": FAILED open or read\n";
            ++failures;
            continue;
        }
        std::string got = to_hex(Hash::hash(data.data(), data.size()));
        bool ok = (got == want);
        std::cout << path << ": " << (ok ? "OK" : "FAILED") << "\n";
        if (!ok) ++failures;
        ++count;
    }
    if (failures) std::cerr << "sha2: " << failures << " of " << count << " did NOT match\n";
    return failures ? 1 : 0;
}

int cmd_hmac(const Options& o) {
    std::vector<std::uint8_t> key;
    std::string err;
    if (!resolve_keyish(o, "key", "key-hex", key, err)) {
        std::cerr << "sha2 hmac: " << err << "\n";
        return 2;
    }
    std::vector<std::uint8_t> data;
    if (!o.positional.empty()) {
        if (!read_file(o.positional[0], data)) {
            std::cerr << "sha2 hmac: cannot read " << o.positional[0] << "\n";
            return 1;
        }
    } else {
        data = read_stream(std::cin);
    }
    auto mac = sha2::HmacSha256::mac(key.data(), key.size(), data.data(), data.size());
    std::cout << to_hex(mac) << "\n";
    return 0;
}

int cmd_hkdf(const Options& o) {
    auto ikm = from_hex(o.get("ikm-hex"));
    if (!ikm) { std::cerr << "sha2 hkdf: --ikm-hex required (hex)\n"; return 2; }
    auto salt = from_hex(o.get("salt-hex", ""));
    auto info = from_hex(o.get("info-hex", ""));
    if (!salt || !info) { std::cerr << "sha2 hkdf: invalid --salt-hex/--info-hex\n"; return 2; }
    std::size_t len = static_cast<std::size_t>(std::stoul(o.get("len", "32")));
    auto okm = sha2::HkdfSha256::derive(salt->data(), salt->size(), ikm->data(), ikm->size(),
                                        info->data(), info->size(), len);
    std::cout << to_hex(okm) << "\n";
    return 0;
}

int cmd_pbkdf2(const Options& o) {
    std::vector<std::uint8_t> pass, salt;
    std::string err;
    if (!resolve_keyish(o, "pass", "pass-hex", pass, err)) {
        std::cerr << "sha2 pbkdf2: " << err << "\n";
        return 2;
    }
    if (!resolve_keyish(o, "salt", "salt-hex", salt, err)) {
        std::cerr << "sha2 pbkdf2: " << err << "\n";
        return 2;
    }
    std::uint32_t iters = static_cast<std::uint32_t>(std::stoul(o.get("iter", "100000")));
    std::size_t len = static_cast<std::size_t>(std::stoul(o.get("len", "32")));
    auto dk = sha2::Pbkdf2HmacSha256::derive(pass.data(), pass.size(), salt.data(), salt.size(),
                                             iters, len);
    std::cout << to_hex(dk) << "\n";
    return 0;
}

int cmd_totp(const Options& o) {
    std::vector<std::uint8_t> key;
    std::string err;
    if (!resolve_keyish(o, "key", "key-hex", key, err)) {
        std::cerr << "sha2 totp: " << err << "\n";
        return 2;
    }
    std::uint64_t now = o.has("time") ? std::stoull(o.get("time"))
                                      : static_cast<std::uint64_t>(std::time(nullptr));
    unsigned digits = static_cast<unsigned>(std::stoul(o.get("digits", "6")));
    std::uint64_t step = std::stoull(o.get("step", "30"));
    std::cout << sha2::totp<sha2::Sha256>(key.data(), key.size(), now, digits, step) << "\n";
    return 0;
}

int cmd_selftest() {
    struct { std::string in, want; } v[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    };
    int bad = 0;
    for (auto& t : v) {
        auto got = to_hex(sha2::Sha256::hash(t.in));
        bool ok = got == t.want;
        std::cout << "[" << (ok ? "ok" : "BAD") << "] sha256(\"" << t.in << "\")\n";
        if (!ok) ++bad;
    }
    std::cout << (bad ? "SELFTEST FAILED" : "SELFTEST OK") << "\n";
    return bad ? 1 : 0;
}

void usage() {
    std::cout <<
        "sha2 — SHA-2 toolkit CLI\n\n"
        "Usage:\n"
        "  sha2 sha256 [FILE...]                 hash files (or stdin), coreutils format\n"
        "  sha2 sha224 [FILE...]\n"
        "  sha2 check  SUMFILE                   verify a 'sha256  file' checksum list\n"
        "  sha2 hmac   --key K | --key-hex H [FILE]\n"
        "  sha2 hkdf   --ikm-hex H [--salt-hex H] [--info-hex H] [--len N]\n"
        "  sha2 pbkdf2 --pass P | --pass-hex H --salt S | --salt-hex H [--iter N] [--len N]\n"
        "  sha2 totp   --key K | --key-hex H [--time UNIX] [--digits N] [--step S]\n"
        "  sha2 selftest\n\n"
        "Examples:\n"
        "  echo -n abc | sha2 sha256\n"
        "  sha2 sha256 firmware.bin > firmware.sha256 && sha2 check firmware.sha256\n"
        "  sha2 hmac --key topsecret message.bin\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    std::string cmd = argv[1];
    Options o = parse(argc, argv, 2);

    if (cmd == "sha256") return cmd_hash<sha2::Sha256>(o);
    if (cmd == "sha224") return cmd_hash<sha2::Sha224>(o);
    if (cmd == "check" || cmd == "-c") return cmd_check<sha2::Sha256>(o);
    if (cmd == "hmac") return cmd_hmac(o);
    if (cmd == "hkdf") return cmd_hkdf(o);
    if (cmd == "pbkdf2") return cmd_pbkdf2(o);
    if (cmd == "totp") return cmd_totp(o);
    if (cmd == "selftest") return cmd_selftest();
    if (cmd == "-h" || cmd == "--help" || cmd == "help") {
        usage();
        return 0;
    }

    std::cerr << "sha2: unknown command '" << cmd << "'\n\n";
    usage();
    return 2;
}
