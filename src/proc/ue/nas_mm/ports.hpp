// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// What the 5GMM entity needs from the layers below it (P1 N5): the UE's RRC
// from N6 on, and a link to the scripted core in the procedure tests. 5GMM
// hands down whole NAS PDUs and learns of releases; how the N1 signalling
// connection is carried is not its business.

#pragma once

#include "platform/buf.hpp"

namespace ksim::proc::ue {

class INasLower {
public:
    virtual ~INasLower() = default;

    /// Sends a NAS PDU. With no N1 signalling connection this sets one up, and
    /// the PDU is the initial NAS message.
    virtual void send_nas(Bytes pdu) = 0;
    /// Releases the N1 signalling connection locally (e.g. §5.5.1.2.7 c). The
    /// lower layers do not call back on_released() for a local release.
    virtual void release_local() = 0;
};

} // namespace ksim::proc::ue
