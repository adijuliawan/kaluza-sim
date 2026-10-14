// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// The UE's 5GMM states (P1 N5; TS 24.501 j80 §5.1.3.2.1) and the transitions
// this entity makes, each with the clause that calls for it. The main states
// 5GMM-DEREGISTERED and 5GMM-REGISTERED are always held in one of their
// substates. A unit test checks the names against spec/nas/24501/mm_states_ue.tsv
// (extracted from the document), and the entity counts any transition it makes
// that the table does not list, which the procedure tests require to be zero.

#pragma once

#include <cstdint>
#include <span>

namespace ksim::proc::ue {

enum class MmState : std::uint8_t {
    null,
    deregistered_normal_service,
    deregistered_limited_service,
    deregistered_attempting_registration,
    deregistered_plmn_search,
    deregistered_no_supi,
    deregistered_no_cell_available,
    deregistered_ecall_inactive,
    deregistered_initial_registration_needed,
    registered_initiated,
    registered_normal_service,
    registered_non_allowed_service,
    registered_attempting_registration_update,
    registered_limited_service,
    registered_plmn_search,
    registered_no_cell_available,
    registered_update_needed,
    deregistered_initiated,
    service_request_initiated,
};

/// The spec's name, "5GMM-DEREGISTERED.NORMAL-SERVICE".
const char* mm_state_name(MmState s) noexcept;
std::span<const MmState> all_mm_states() noexcept;
bool is_deregistered(MmState s) noexcept;   // a 5GMM-DEREGISTERED substate
bool is_registered(MmState s) noexcept;     // a 5GMM-REGISTERED substate

/// The 5GS update status (§5.1.3.2.2).
enum class UpdateStatus : std::uint8_t { u1_updated, u2_not_updated, u3_roaming_not_allowed };
const char* update_status_name(UpdateStatus u) noexcept;

struct MmTransition {
    MmState from;
    MmState to;
    const char* clause;
};

/// Every transition the entity makes.
std::span<const MmTransition> mm_transitions() noexcept;
const MmTransition* find_transition(MmState from, MmState to) noexcept;

} // namespace ksim::proc::ue
