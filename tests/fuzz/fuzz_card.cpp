// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The soft card under arbitrary APDU streams (P1 N3): an input is a sequence of
// (length octet, command APDU), run against a fresh card from the template.
// Whatever arrives, the card answers with a response APDU of at least SW1 SW2
// and never crashes, reads out of bounds or leaks (ASan and UBSan watch).

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

#include "platform/yaml.hpp"
#include "uicc/image/image.hpp"
#include "uicc/secrets/secrets.hpp"

namespace {

const ksim::Yaml& template_image() {
    static const ksim::Yaml y = ksim::Yaml::load_file(std::string(KSIM_SOURCE_DIR) + "/cards/usim-5g.yaml");
    return y;
}

ksim::SecretBytes ascii(const char* s) {
    return ksim::SecretBytes::copy_of(ksim::ByteView(reinterpret_cast<const std::uint8_t*>(s), std::char_traits<char>::length(s)));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    ksim::uicc::secrets::SecretMap s;
    s.set("k", ksim::SecretBytes(16));
    s.set("opc", ksim::SecretBytes(16));
    s.set("pin1", ascii("1234"));
    s.set("puk1", ascii("12345678"));
    s.set("pin2", ascii("5678"));
    s.set("puk2", ascii("87654321"));
    s.set("adm1", ascii("11111111"));
    auto card = ksim::uicc::image::load(template_image(), s);
    std::size_t at = 0;
    while (at < size) {
        const std::size_t n = data[at++];
        const std::size_t take = n < size - at ? n : size - at;
        const ksim::Bytes out = card->process(ksim::ByteView(data + at, take));
        if (out.size() < 2) {
            std::abort();
        }
        at += take;
    }
    return 0;
}
