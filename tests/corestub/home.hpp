// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The core stub's home functions (P1 N5, ADR 0009 point f): the UDM/ARPF and
// AUSF of TS 33.501 §6.1.3.2 for the test subscribers. Authentication vectors
// come from each subscriber's K and OPc with Milenage, SQN = SEQ ‖ IND with a
// five-bit IND of 0 (TS 33.102 Annex C.3.2), and AMF 8000 (the separation bit
// set). Re-synchronisation checks MAC-S and takes SEQ_MS from AUTS (TS 33.102
// §6.3.5). Every value is derived from spec text and the KAT-backed crypto
// layer, never from a core under test.

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "platform/buf.hpp"
#include "platform/result.hpp"
#include "platform/rng.hpp"
#include "platform/secret.hpp"

namespace ksim::corestub {

/// One 5G authentication vector as the AMF holds it (the AUSF keeps XRES*
/// and K_AUSF; the stub plays both).
struct Av {
    Bytes rand;
    Bytes autn;
    SecretBytes xres_star;
    SecretBytes kamf;
};

struct AvOptions {
    bool corrupt_mac = false;       // a MAC the USIM must refuse (#20)
    bool separation_bit = true;     // AMF bit 0 (#26 when clear)
    std::optional<std::uint64_t> seq;   // a SEQ of the test's choosing (a stale one gives #21)
};

class Home {
public:
    explicit Home(Rng rng) : rng_(rng) {}

    void add(std::string supi, SecretBytes k, SecretBytes opc, std::uint64_t seq = 0);
    bool has(const std::string& supi) const { return subs_.count(supi) != 0; }
    /// The SUPI with this PLMN and MSIN, or empty.
    std::string find(std::string_view mcc, std::string_view mnc, std::string_view msin) const;
    std::uint64_t seq(const std::string& supi) const;

    /// A fresh vector for the serving network name and ABBA; SEQ advances.
    Result<Av> make_av(const std::string& supi, std::string_view snn, ByteView abba, const AvOptions& o = {});
    /// Re-synchronisation from AUTS: false when MAC-S does not verify.
    Result<bool> resync(const std::string& supi, ByteView rand, ByteView auts);

private:
    struct Sub {
        SecretBytes k;
        SecretBytes opc;
        std::uint64_t seq = 0;   // SEQ_HE, the last one used
    };
    Rng rng_;
    std::map<std::string, Sub> subs_;
};

} // namespace ksim::corestub
