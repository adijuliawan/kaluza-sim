#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook: the pinned spec documents match spec/INDEX.tsv (plan M3).
# Exit 77 (SKIP) on a fresh clone without fetched documents.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 "$ROOT/spec/tools/verify_index.py" --self-test || exit 1
python3 "$ROOT/spec/tools/verify_index.py"
