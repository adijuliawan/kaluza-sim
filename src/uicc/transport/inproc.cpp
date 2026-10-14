// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include <utility>

#include "uicc/transport/transport.hpp"

namespace ksim::uicc {

void InProcTransport::reset(Done done) {
    Result<Bytes> answer = card_ != nullptr ? Result<Bytes>(card_->reset())
                                            : Result<Bytes>(make_error(Errc::closed, 0, "uicc: no card in the reader"));
    exec_.post([done = std::move(done), answer = std::move(answer)]() mutable { done(std::move(answer)); });
}

void InProcTransport::transmit(Bytes capdu, Done done) {
    Result<Bytes> answer = card_ != nullptr ? Result<Bytes>(card_->process(capdu))
                                            : Result<Bytes>(make_error(Errc::closed, 0, "uicc: no card in the reader"));
    secure_zero(capdu);
    exec_.post([done = std::move(done), answer = std::move(answer)]() mutable { done(std::move(answer)); });
}

} // namespace ksim::uicc
