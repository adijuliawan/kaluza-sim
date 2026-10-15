// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The vpcd framing and the APDU trace under arbitrary bytes (P1 N14): the
// input is cut where its first octet says and fed to a soft card behind
// VpcdCard, each answered exchange going through the trace's Redactor; then
// the rest is read as (length, command, length, response) pairs straight into
// a second Redactor. Every frame the card sends is well formed, every record
// keeps at least its header, nothing crashes or reads out of bounds.

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "platform/transport.hpp"
#include "platform/yaml.hpp"
#include "uicc/image/image.hpp"
#include "uicc/secrets/secrets.hpp"
#include "uicc/trace/trace.hpp"
#include "uicc/transport/vpcd.hpp"

namespace {

const ksim::Yaml& template_image() {
    static const ksim::Yaml y = ksim::Yaml::load_file(std::string(KSIM_SOURCE_DIR) + "/cards/usim-5g.yaml");
    return y;
}

ksim::SecretBytes ascii(const char* s) {
    return ksim::SecretBytes::copy_of(ksim::ByteView(reinterpret_cast<const std::uint8_t*>(s), std::char_traits<char>::length(s)));
}

/// What the card sends is checked to be whole frames.
class Stream final : public ksim::IStream {
public:
    void set_handlers(OnData on_data, OnClosed /*on_closed*/) override { on_data_ = std::move(on_data); }
    ksim::Result<void> send(ksim::ByteView data) override {
        if (data.size() < 2 || data.size() != 2 + (static_cast<std::size_t>(data[0]) << 8 | data[1])) {
            std::abort();
        }
        return {};
    }
    bool open() const noexcept override { return true; }
    void close() override {}
    ksim::Endpoint peer() const override { return {}; }
    void feed(ksim::ByteView d) const {
        if (on_data_) {
            on_data_(d);
        }
    }

private:
    OnData on_data_;
};

void check(const std::vector<ksim::Bytes>& recs) {
    for (const auto& r : recs) {
        if (r.empty()) {
            std::abort();
        }
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    ksim::uicc::secrets::SecretMap s;
    s.set("k", ksim::SecretBytes(16));
    s.set("opc", ksim::SecretBytes(16));
    s.set("pin1", ascii("1234"));
    s.set("adm1", ascii("11111111"));
    auto card = ksim::uicc::image::load(template_image(), s);
    Stream stream;
    ksim::uicc::trace::Redactor red;
    {
        ksim::uicc::vpcd::VpcdCard vc(stream, *card, [&](ksim::ByteView c, ksim::ByteView r) {
            if (!c.empty()) {
                check(red.apply(c, r));
            }
        });
        const std::size_t cut = 1 + data[0] % 7;   // pieces of 1..7 octets
        const std::size_t half = size / 2;
        for (std::size_t at = 1; at < half; at += cut) {
            stream.feed(ksim::ByteView(data + at, std::min(cut, half - at)));
        }
        check(red.flush());
    }
    ksim::uicc::trace::Redactor raw;
    std::size_t at = size / 2;
    while (at + 2 <= size) {
        const std::size_t want_c = data[at];
        ++at;
        const std::size_t nc = std::min(want_c, size - at);
        const ksim::ByteView c(data + at, nc);
        at += nc;
        std::size_t nr = 0;
        if (at < size) {
            const std::size_t want_r = data[at];
            ++at;
            nr = std::min(want_r, size - at);
        }
        const ksim::ByteView r(data + at, nr);
        at += nr;
        check(raw.apply(c, r));
    }
    check(raw.flush());
    return 0;
}
