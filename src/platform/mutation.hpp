// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// Sim mutants (P1 N1, ADR 0009 point 6; verification.md §1): every scenario row
// has a switch that makes the sim misbehave in exactly the way that row exists
// to catch, and the row must then fail. A site reads
//
//     if (KSIM_MUTANT("null_suci_full_imsi")) { …the wrong behaviour… }
//
// In a normal build every site is the constant false and compiles away. Only a
// build configured with -DKSIM_MUTATIONS=ON (preset `mutants`) tests the
// switch, and only the one mutant named by the environment variable
// KSIM_MUTANT is on, for the whole process. Names are literals, listed with
// their row in tests/mutants.tsv; tools/guards/check_mutants.py keeps the two
// in step. A mutant build never runs against a real core (`ksim` refuses).

#pragma once

#include <string_view>

namespace ksim {

/// True when this is a mutant build (KSIM_MUTATIONS=ON).
constexpr bool kMutationsBuild =
#if defined(KSIM_MUTATIONS) && KSIM_MUTATIONS
    true;
#else
    false;
#endif

/// The mutant switched on for this process ("" when none, or in a normal build).
std::string_view active_mutant() noexcept;
bool mutant_active(std::string_view name) noexcept;

namespace testing {

/// Switches one mutant on for a scope, so a procedure test can show the check
/// that kills it (a mutant build's tests only; a normal build ignores it).
/// Single-threaded tests only.
class MutantScope {
public:
    explicit MutantScope(std::string_view name);
    ~MutantScope();
    MutantScope(const MutantScope&) = delete;
    MutantScope& operator=(const MutantScope&) = delete;
};

} // namespace testing

} // namespace ksim

#if defined(KSIM_MUTATIONS) && KSIM_MUTATIONS
#define KSIM_MUTANT(name) (::ksim::mutant_active(name))
#else
#define KSIM_MUTANT(name) (false)
#endif
