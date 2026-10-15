# OCUDU SNOW 3G kernel (verbatim copy)

From OCUDU (https://gitlab.com/ocudu/ocudu) at 489ed15c5cd6b1d4f52cf16c2e4cc79c2bde1775,
BSD-3-Clause-Open-MPI (ADR 0004: OCUDU code may be copied with its header and a NOTICE entry):

| Here | OCUDU |
|---|---|
| `include/ocudu/security/s3g.h` | `include/ocudu/security/s3g.h` |
| `src/s3g.cpp` | `lib/security/s3g.cpp` |
| `src/s3g.h` | `lib/security/s3g.h` |

The files are unmodified; `MANIFEST.sha256` holds their hashes and CI checks them.
`shim/ocudu/security/security.h` is ours: it defines the one type (`sec_mac`)
the copy needs from OCUDU's own `security.h`.

Use: the SNOW 3G keystream generator and UIA2's f9, under kaluza-sim's
128-NEA1/128-NIA1 wrappers (in `src/crypto/nea.cpp`). SNOW 3G is subject to the
GSMA restricted usage undertaking held by the repository owner.
