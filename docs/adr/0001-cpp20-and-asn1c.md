# ADR 0001: C++20, with ASN.1 through asn1c

- **Status:** accepted, 2026-10-14 (user)
- **Context:**
  - The simulator needs Rel-19 PER codecs: RRC (UPER), and NGAP, F1AP, E1AP and XnAP (APER). Later it also needs NRPPa, LPP and the E2 protocols.
  - It also needs a slot-capable event loop for about 100 full-stack UEs, eBPF later, PC/SC access to real cards, and (phase 2) NETCONF/YANG.
  - The hardest part is ASN.1. On this machine, asn1c (mouse07410 fork, commit 18e56503) already generates Rel-19 v19.3.0 RRC, NGAP, F1AP and E1AP in the UERANSIM fork, and kaluza-ue builds TS 38.331 v19.3.0 with asn1c.
- **Decision:** C++20.
  - asn1c (mouse07410 at 18e56503, BSD-2) generates the codecs from ASN.1 that **our own** clean-room tool extracts from the Rel-19 docx. Each protocol becomes a static library, and hand-written code reaches it only through thin RAII and visitor wrappers.
  - NAS (not ASN.1) is generated from tables that our own tool extracts from TS 24.501.
- **Consequences:**
  - The C libraries are used natively: OpenSSL, libbpf, pcsc-lite, netopeer2/sysrepo/libyang.
  - OCUDU (C++17, BSD) can be read, and copied with attribution, for PDCP, security, SDAP, GTP-U and NR-U.
  - Memory safety must be earned: ASan/UBSan/TSan presets, libFuzzer on every decoder, clang-tidy, and the layer checker.
  - asn1c's output is large and slow to compile, so it is built as one library per protocol with stamp caching and ccache.
  - The fork's HEAD and stock 0.9.29 do not work for Rel-16+ application protocols, so the commit pin is mandatory.
- **Alternatives considered:**
  - **Rust:** safe and fast, with aya for eBPF, but the Rust ASN.1 compilers are unproven for Rel-19 RRC, and asn1c output would go through FFI. There is no existing Rust codebase.
  - **Go:** the user's eUPF, UPF-VPP CP and n3iwue are Go, and PacketRusher's eBPF code could be reused. But there is no good Rel-19 PER generator; cgo plus asn1c means slow builds and awkward memory.
  - **Java 25:** the user's main language, but it invites sharing kaluza-core's codecs ([ADR 0005](0005-independence-from-kaluza-core.md)), and its eBPF integration is weak.
