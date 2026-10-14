// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "uicc/os/keyfile.hpp"

#include <algorithm>

namespace ksim::uicc::os {

void write_key_file(File& f, std::size_t offset, ByteView data) {
    auto dst = f.secret_data.expose_mut();
    if (offset + data.size() <= dst.size()) {
        std::copy(data.begin(), data.end(), dst.begin() + static_cast<std::ptrdiff_t>(offset));
    }
}

SecretBytes key_slice(const File& f, std::size_t offset, std::size_t len) {
    const ByteView all = f.secret_data.expose();
    if (offset + len > all.size()) {
        return {};
    }
    return SecretBytes::copy_of(all.subspan(offset, len));
}

std::uint8_t key_byte(const File& f, std::size_t offset, std::uint8_t fallback) {
    const ByteView all = f.secret_data.expose();
    return offset < all.size() ? all[offset] : fallback;
}

} // namespace ksim::uicc::os
