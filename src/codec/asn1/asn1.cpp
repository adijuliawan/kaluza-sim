// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "codec/asn1/asn1.hpp"

#include <cstring>

extern "C" {
#include "asn_application.h"
#include "asn_internal.h"
#include "constraints.h"
}

namespace ksim::asn1 {

namespace {

asn_codec_ctx_t codec_ctx() {
    asn_codec_ctx_t ctx{};
    ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;  // bounded recursion for hostile input
    return ctx;
}

asn_transfer_syntax syntax(Rules r) {
    return r == Rules::aper ? ATS_ALIGNED_BASIC_PER : ATS_UNALIGNED_BASIC_PER;
}

Error err(Errc c, std::size_t off, const char* what) {
    return make_error(c, static_cast<std::uint32_t>(off), what);
}

} // namespace

void detail::free_struct(const asn_TYPE_descriptor_t& td, void* p) noexcept {
    ASN_STRUCT_FREE(td, p);
}

Result<Owned<>> decode(const asn_TYPE_descriptor_t& td, Rules rules, ByteView in) {
    asn_codec_ctx_t ctx = codec_ctx();
    void* p = nullptr;
    const asn_dec_rval_t rv = asn_decode(&ctx, syntax(rules), &td, &p, in.data(), in.size());
    Owned<> out(td, p);
    if (rv.code != RC_OK) {
        return err(rv.code == RC_WMORE ? Errc::truncated : Errc::malformed, rv.consumed, "PER decode failed");
    }
    if (rv.consumed < in.size()) {
        return err(Errc::malformed, rv.consumed, "trailing octets after the PDU");
    }
    return out;
}

Result<Bytes> encode(const asn_TYPE_descriptor_t& td, const void* value, Rules rules, Check check) {
    if (check == Check::strict) {
        if (auto ok = check_constraints(td, value); !ok) {
            return ok.error();
        }
    }
    asn_codec_ctx_t ctx = codec_ctx();
    const asn_encode_to_new_buffer_result_t r = asn_encode_to_new_buffer(&ctx, syntax(rules), &td, value);
    if (r.buffer == nullptr || r.result.encoded < 0) {
        std::free(r.buffer);
        return err(Errc::invalid_argument, 0, "PER encode failed");
    }
    const auto* b = static_cast<const std::uint8_t*>(r.buffer);
    Bytes out(b, b + r.result.encoded);
    std::free(r.buffer);
    return out;
}

Result<std::string> to_jer(const asn_TYPE_descriptor_t& td, const void* value, bool minified) {
    asn_codec_ctx_t ctx = codec_ctx();
    const asn_encode_to_new_buffer_result_t r =
        asn_encode_to_new_buffer(&ctx, minified ? ATS_JER_MINIFIED : ATS_JER, &td, value);
    if (r.buffer == nullptr || r.result.encoded < 0) {
        std::free(r.buffer);
        return err(Errc::invalid_argument, 0, "JER encode failed");
    }
    std::string out(static_cast<const char*>(r.buffer), static_cast<std::size_t>(r.result.encoded));
    std::free(r.buffer);
    return out;
}

Result<Owned<>> from_jer(const asn_TYPE_descriptor_t& td, std::string_view jer) {
    asn_codec_ctx_t ctx = codec_ctx();
    void* p = nullptr;
    const asn_dec_rval_t rv = asn_decode(&ctx, ATS_JER, &td, &p, jer.data(), jer.size());
    Owned<> out(td, p);
    if (rv.code != RC_OK) {
        return err(rv.code == RC_WMORE ? Errc::truncated : Errc::malformed, rv.consumed, "JER decode failed");
    }
    return out;
}

Result<void> check_constraints(const asn_TYPE_descriptor_t& td, const void* value, std::string* why) {
    char buf[256] = {};
    std::size_t len = sizeof buf;
    if (asn_check_constraints(&td, value, buf, &len) != 0) {
        if (why != nullptr) {
            why->assign(buf, std::strlen(buf));
        }
        return err(Errc::out_of_range, 0, "constraint check failed");
    }
    return {};
}

} // namespace ksim::asn1
