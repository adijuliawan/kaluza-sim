// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The fuzz smoke's must-fail target (plan M14): it crashes on an input that
// starts with "KSIM", which its seed does, so a smoke run that reports no
// crash here is a broken harness, not a clean codec.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size >= 4 && std::memcmp(data, "KSIM", 4) == 0) {
        std::abort();
    }
    return 0;
}
