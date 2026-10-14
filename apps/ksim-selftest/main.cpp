// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// ksim-selftest: the build identity as KEY=value lines (cli.md output style),
// then the self-checks. Exit 0 when every check passes.

#include <cstdio>
#include <cstring>

#include "ksim/build_info.hpp"

namespace {

void print_identity() {
    std::printf("KSIM_VERSION=%s\n", ksim::build::kVersion);
    std::printf("COMMIT=%s\n", ksim::build::kGitDescribe);
    std::printf("BUILD_TYPE=%s\n", ksim::build::kBuildType);
    std::printf("SANITIZE=%s\n", ksim::build::kSanitize);
    std::printf("ARCH_FLAGS=%s\n", ksim::build::kArchFlags);
    std::printf("CXX=%s\n", ksim::build::kCxxCompiler);
    std::printf("CONFIGURED_UTC=%s\n", ksim::build::kConfigureUtc);
}

} // namespace

int main(int argc, char** argv) {
    print_identity();
    if (argc > 1 && std::strcmp(argv[1], "--version") == 0) {
        return 0;
    }
    std::printf("CHECKS=0\nFAILED=0\n");
    return 0;
}
