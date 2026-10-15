// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private

#include "proc/ue/nas_mm/state.hpp"

#include <array>

namespace ksim::proc::ue {

namespace {

using S = MmState;

constexpr std::array kStates{
    S::null,
    S::deregistered_normal_service,
    S::deregistered_limited_service,
    S::deregistered_attempting_registration,
    S::deregistered_plmn_search,
    S::deregistered_no_supi,
    S::deregistered_no_cell_available,
    S::deregistered_ecall_inactive,
    S::deregistered_initial_registration_needed,
    S::registered_initiated,
    S::registered_normal_service,
    S::registered_non_allowed_service,
    S::registered_attempting_registration_update,
    S::registered_limited_service,
    S::registered_plmn_search,
    S::registered_no_cell_available,
    S::registered_update_needed,
    S::deregistered_initiated,
    S::service_request_initiated,
};

// Every transition the 5GMM entity makes, with the clause that calls for it.
constexpr std::array kTransitions{
    MmTransition{S::null, S::deregistered_normal_service, "5.2.2.2.1"},
    MmTransition{S::null, S::deregistered_no_supi, "5.2.2.2.1"},
    MmTransition{S::deregistered_normal_service, S::registered_initiated, "5.5.1.2.2"},
    MmTransition{S::deregistered_limited_service, S::registered_initiated, "5.5.1.2.2"},
    MmTransition{S::deregistered_plmn_search, S::registered_initiated, "5.5.1.2.2"},
    MmTransition{S::deregistered_attempting_registration, S::registered_initiated, "5.5.1.2.7"},
    MmTransition{S::registered_initiated, S::registered_normal_service, "5.5.1.2.4"},
    MmTransition{S::registered_initiated, S::deregistered_attempting_registration, "5.5.1.2.7"},
    MmTransition{S::registered_initiated, S::deregistered_no_supi, "5.5.1.2.5, 5.4.1.3.5"},
    MmTransition{S::registered_initiated, S::deregistered_plmn_search, "5.5.1.2.5"},
    MmTransition{S::registered_initiated, S::deregistered_limited_service, "5.5.1.2.5"},
    MmTransition{S::registered_initiated, S::deregistered_initiated, "5.5.1.2.7 f, 5.5.2.2.1"},
    MmTransition{S::registered_initiated, S::null, "5.5.1.2.7 f, 5.5.2.2.1"},
    MmTransition{S::registered_normal_service, S::deregistered_initiated, "5.5.2.2.1"},
    MmTransition{S::registered_normal_service, S::null, "5.5.2.2.1"},
    MmTransition{S::registered_normal_service, S::deregistered_no_supi, "5.4.1.3.5"},
    MmTransition{S::deregistered_initiated, S::deregistered_normal_service, "5.5.2.2.2, 5.5.2.2.6"},
    MmTransition{S::deregistered_initiated, S::deregistered_no_supi, "5.4.1.3.5"},
    // N12
    MmTransition{S::registered_normal_service, S::registered_initiated, "5.5.1.3.2"},
    MmTransition{S::registered_normal_service, S::service_request_initiated, "5.6.1.2"},
    MmTransition{S::service_request_initiated, S::registered_normal_service, "5.6.1.4, 5.6.1.5, 5.6.1.7"},
    MmTransition{S::service_request_initiated, S::deregistered_normal_service, "5.6.1.5"},
    MmTransition{S::registered_normal_service, S::deregistered_normal_service, "5.5.2.3.2"},
    MmTransition{S::registered_initiated, S::deregistered_normal_service, "5.5.2.3.2"},
    MmTransition{S::service_request_initiated, S::null, "power off"},
    MmTransition{S::deregistered_normal_service, S::null, "power off"},
    MmTransition{S::deregistered_initiated, S::null, "power off"},
    MmTransition{S::deregistered_attempting_registration, S::null, "power off"},
    MmTransition{S::deregistered_limited_service, S::null, "power off"},
    MmTransition{S::deregistered_plmn_search, S::null, "power off"},
    MmTransition{S::deregistered_no_supi, S::null, "power off"},
    // N12 follow-up: §5.3.20 for a service reject; the network de-registration's
    // causes (§5.5.2.3.2, §5.5.2.3.4 b), also met during the UE's own (§5.5.2.2.6 d).
    MmTransition{S::service_request_initiated, S::deregistered_limited_service, "5.3.20.2"},
    MmTransition{S::registered_normal_service, S::deregistered_plmn_search, "5.5.2.3.2"},
    MmTransition{S::registered_normal_service, S::deregistered_limited_service, "5.5.2.3.2"},
    MmTransition{S::registered_normal_service, S::deregistered_attempting_registration, "5.5.2.3.2, 5.5.2.3.4 b"},
    MmTransition{S::registered_initiated, S::deregistered_attempting_registration, "5.5.2.3.4 b"},
    MmTransition{S::service_request_initiated, S::deregistered_no_supi, "5.5.2.3.2"},
    MmTransition{S::service_request_initiated, S::deregistered_plmn_search, "5.5.2.3.2"},
    MmTransition{S::service_request_initiated, S::deregistered_attempting_registration, "5.5.2.3.2, 5.5.2.3.4 b"},
    MmTransition{S::deregistered_initiated, S::deregistered_plmn_search, "5.5.2.2.6 d"},
    MmTransition{S::deregistered_initiated, S::deregistered_limited_service, "5.5.2.2.6 d"},
    MmTransition{S::deregistered_initiated, S::deregistered_attempting_registration, "5.5.2.2.6 d"},
    // The UICC removed and inserted again (§5.5.2.2.1, 5.2.2.2.1).
    MmTransition{S::deregistered_normal_service, S::deregistered_no_supi, "5.5.2.2.1"},
    MmTransition{S::deregistered_limited_service, S::deregistered_no_supi, "5.5.2.2.1"},
    MmTransition{S::deregistered_attempting_registration, S::deregistered_no_supi, "5.5.2.2.1"},
    MmTransition{S::deregistered_plmn_search, S::deregistered_no_supi, "5.5.2.2.1"},
    MmTransition{S::deregistered_no_supi, S::deregistered_normal_service, "5.2.2.2.1"},
};

} // namespace

const char* mm_state_name(MmState s) noexcept {
    switch (s) {
    case S::null: return "5GMM-NULL";
    case S::deregistered_normal_service: return "5GMM-DEREGISTERED.NORMAL-SERVICE";
    case S::deregistered_limited_service: return "5GMM-DEREGISTERED.LIMITED-SERVICE";
    case S::deregistered_attempting_registration: return "5GMM-DEREGISTERED.ATTEMPTING-REGISTRATION";
    case S::deregistered_plmn_search: return "5GMM-DEREGISTERED.PLMN-SEARCH";
    case S::deregistered_no_supi: return "5GMM-DEREGISTERED.NO-SUPI";
    case S::deregistered_no_cell_available: return "5GMM-DEREGISTERED.NO-CELL-AVAILABLE";
    case S::deregistered_ecall_inactive: return "5GMM-DEREGISTERED.eCALL-INACTIVE";
    case S::deregistered_initial_registration_needed: return "5GMM-DEREGISTERED.INITIAL-REGISTRATION-NEEDED";
    case S::registered_initiated: return "5GMM-REGISTERED-INITIATED";
    case S::registered_normal_service: return "5GMM-REGISTERED.NORMAL-SERVICE";
    case S::registered_non_allowed_service: return "5GMM-REGISTERED.NON-ALLOWED-SERVICE";
    case S::registered_attempting_registration_update: return "5GMM-REGISTERED.ATTEMPTING-REGISTRATION-UPDATE";
    case S::registered_limited_service: return "5GMM-REGISTERED.LIMITED-SERVICE";
    case S::registered_plmn_search: return "5GMM-REGISTERED.PLMN-SEARCH";
    case S::registered_no_cell_available: return "5GMM-REGISTERED.NO-CELL-AVAILABLE";
    case S::registered_update_needed: return "5GMM-REGISTERED.UPDATE-NEEDED";
    case S::deregistered_initiated: return "5GMM-DEREGISTERED-INITIATED";
    case S::service_request_initiated: return "5GMM-SERVICE-REQUEST-INITIATED";
    }
    return "?";
}

std::span<const MmState> all_mm_states() noexcept { return kStates; }

bool is_deregistered(MmState s) noexcept {
    return s >= S::deregistered_normal_service && s <= S::deregistered_initial_registration_needed;
}

bool is_registered(MmState s) noexcept { return s >= S::registered_normal_service && s <= S::registered_update_needed; }

const char* update_status_name(UpdateStatus u) noexcept {
    switch (u) {
    case UpdateStatus::u1_updated: return "5U1 UPDATED";
    case UpdateStatus::u2_not_updated: return "5U2 NOT UPDATED";
    case UpdateStatus::u3_roaming_not_allowed: return "5U3 ROAMING NOT ALLOWED";
    }
    return "?";
}

std::span<const MmTransition> mm_transitions() noexcept { return kTransitions; }

const MmTransition* find_transition(MmState from, MmState to) noexcept {
    for (const auto& t : kTransitions) {
        if (t.from == from && t.to == to) {
            return &t;
        }
    }
    return nullptr;
}

} // namespace ksim::proc::ue
