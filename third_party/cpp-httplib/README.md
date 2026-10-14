# cpp-httplib (vendored)

`httplib.h` and `LICENSE` from https://github.com/yhirose/cpp-httplib at tag v0.26.0, unmodified (MIT). The single-header
form, so the deployed binaries need no shared library on kaluza-uesim (ADR 0009, point 7). `MANIFEST.sha256` holds the
header's hash, checked by `tools/ci.d/25-third-party.sh`. Used only by the control API (`src/api`), from P1 N8.
