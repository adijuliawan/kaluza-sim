#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# CI hook (plan M14): the secret canary. tests/canary's ksim_canary sends a
# known K through the key paths and writes a log, a capture and JSON; none may
# hold K or a key derived from it in any form, and the two deliberate leaks
# must be found.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 "$ROOT/tools/secret_canary.py" --binary "$ROOT/build/dev/tests/canary/ksim_canary"
