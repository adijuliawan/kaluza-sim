// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Replay driver for fuzz targets in builds without libFuzzer: feeds every file
// of the given files or directories to LLVMFuzzerTestOneInput once. A crash or
// sanitizer report fails the ctest.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace {

int run_file(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "replay: cannot open %s\n", p.c_str());
        return 1;
    }
    std::vector<char> buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(buf.data()), buf.size());
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    int failures = 0;
    std::size_t files = 0;
    for (int i = 1; i < argc; ++i) {
        const std::filesystem::path arg(argv[i]);
        if (std::filesystem::is_directory(arg)) {
            for (const auto& e : std::filesystem::recursive_directory_iterator(arg)) {
                if (e.is_regular_file()) {
                    failures += run_file(e.path());
                    ++files;
                }
            }
        } else {
            failures += run_file(arg);
            ++files;
        }
    }
    std::printf("REPLAYED=%zu FAILED_OPEN=%d\n", files, failures);
    return failures == 0 ? 0 : 1;
}
