# Research: the UERANSIM fork (read-only survey, 2026-10-14)

**Tree:** `/home/amadeus/Development/UERANSIM`, main, 16 commits ahead of `origin/main`. Upstream v3.3.0 is merged (`055c34a8`). Worktrees:
- `UERANSIM-w27b` (`w27-ps-modify`);
- `UERANSIM-w17fix`;
- `UERANSIM-w38b` (`w38b-ipv6`);
- `UERANSIM-f3` (`f3-sms`, including w38b's commits).

**Licence: AGPL-3.0.** Read for facts and ideas only; nothing is copied ([ADR 0004](../adr/0004-clean-room-licensing.md)).

## Architecture

- **Build:** C++17. Binaries `nr-ue`, `nr-gnb`, `nr-gnb-du`, `nr-gnb-cu`, `nr-gnb-cu-cp`, `nr-gnb-cu-up`, `nr-cli`. `external/liboqs` provides ML-KEM-768.
- **Threads:** each task is a thread with a message deque and a timer heap (`src/utils/nts.hpp`).
  - Per UE: NAS, RRC, App and RLS tasks, plus an RLS UDP task and an RLS control task.
  - Per PDU session: a TUN task and a reader thread.
  - That is **6–8 threads per UE**, with at most **512 UEs per process**.
- **Radio Link Simulation (RLS)** (`src/lib/rls/rls_pdu.hpp`), over UDP port 4997. Four messages: HEARTBEAT (UE position), HEARTBEAT_ACK (dBm), PDU_TRANSMISSION (RRC or DATA), PDU_TRANSMISSION_ACK.
  - Signal strength is minus the distance, with a −120 dBm floor.
  - 3 s without an ACK means radio link failure.
  - The pseudo-PCI is NCI mod 1008, so cells can collide.
- **What is actually simulated:** only UPER RRC messages and raw IP. **No PDCP, RLC, MAC or PHY, and no AS security**; in F1 framing the MAC-I is zero.
  - UE RRC handles MIB, SIB1, RRCSetup/Reject, DLInformationTransfer, RRCRelease, RRCReconfiguration and Paging.
  - On the gNB, Resume, Reestablishment, SecurityModeComplete, MeasurementReport and UECapabilityInformation are TODO.
  - `RRC_INACTIVE` exists in the enum with no behaviour.
- **User plane:** a TUN `uesimtun<N>` per PDU session (MTU 1400) with a per-TUN routing table in `/etc/iproute2/rt_tables` (`src/ue/tun/config.cpp`). The gNB does GTP-U in user space, with an optional fast path (`src/gnb/gtp/fastpath.hpp`).
- **SIM:** YAML keys and software Milenage. No APDUs, no EF model. SUCI: null scheme and Profile A on main (Profile B, TUAK and MILENAGE-256 are on the unmerged `pqc-256bit` branch).

## The ASN.1 pipeline (facts used by kaluza-sim's P0; code not copied)

- **Compiler:** asn1c, the **mouse07410 fork at commit 18e56503** (2024-08-21, reports 0.9.29).
  - The fork's HEAD (2025/26) fails on parameterized containers (`ProtocolIE-Container` etc.) with about 1,470 FATALs on NGAP.
  - Stock vlm 0.9.29 cannot parse Rel-16+ `[[ ]]` CHOICE brackets.
  - The `#if` guards on `encoding_constraints` need post-processing.
- **Generated trees, committed at v19.3.0:** RRC (5,241 files, UPER), NGAP (2,617), F1AP (3,705), E1AP (TS 37.483, 1,303), all APER. Container type names encode source line numbers. One generated width bug was caught only by Wireshark: SRBID came out as 3 bits.
- **Notes:** `/home/amadeus/Development/UERANSIM/tools/README-asn1.md`. The pipeline is `tools/asn1-from-docx.py` then `regen-asn1.sh`.

## Fork additions (main and branches)

- **On main:**
  - EAP-AKA′ hardening and PQC variants; NSSAA; one EAP peer for NSSAA and secondary authentication (PAP, CHAP, EAP);
  - LBO and home-routed roaming;
  - T3396 back-off and UAC; SNPN access mode (NID in SIB1);
  - N2 handover with cancel and failure paths; Xn handover over a **custom UDP link** plus Path Switch;
  - a real CU/DU split with F1-C, F1-U and E1AP, and inter-DU handover;
  - PDU Session Resource Modify and NAS modification; UL classifier; QFI in GTP-U;
  - Rel-19 ASN.1 bumps.
- **Not merged:**
  - `f3-sms`: SMS over NAS;
  - `w38b-ipv6`;
  - `aiot-reader`: Rel-19 Ambient IoT;
  - `ethernet-pdu`: Ethernet PDU sessions on TAP;
  - `pqc-256bit`.
- **Absent everywhere:** RRC_INACTIVE, measurement reporting, CHO, handover data forwarding, NRPPa/LPP, URSP, MBS, RedCap, ATSSS, CIoT, AKMA, emergency, EAP-TLS/TTLS primary authentication, non-3GPP.

## Limits that matter to kaluza-core

The full list, with sources and kaluza-sim's rule for each, is in [`../requirements.md`](../requirements.md) §3.1 (L1–L15). The key points:
- no UE CONTEXT RELEASE REQUEST on radio loss;
- no re-registration after "re-registration required" (`src/ue/nas/mm/dereg.cpp`: a TODO);
- #29 back-off ignored;
- the downlink QFI ignored;
- an empty RP-DA;
- hard-coded Path Switch security capabilities;
- the gNB never re-associates after an AMF restart;
- host IPv6 noise into the TUNs (P-33).

**Performance:** about 180 Mbit/s originally, about 350/470 Mbit/s UL/DL per UE after its fast path (`/home/amadeus/Development/UERANSIM/USERPLANE-PERF-DEV.md`). A TC-BPF phase was not built.

**Previous comparison with PacketRusher:** `/home/amadeus/Development/UERANSIM/UERANSIM-vs-packetrusher-evaluation.md`.

## How kaluza-core's gates drive it

- **Gate scripts:** POSIX sh at `/home/amadeus/Development/kaluza-core/misc/<nf>/verification/kaluza-*.sh`, sourcing `misc/gate/kaluza-deploy.sh` (`UE_HOST=kaluza-uesim`, `UE_ADDR=172.30.30.20`).
- **Start:** over SSH, `setsid -f nohup build/nr-gnb -c …`, then `nr-ue`. Stopped with `pkill -x`.
- **Driving:** `build/nr-cli <imsi|gnb> --exec '…'`. The command set is in [`../verification.md`](../verification.md) §6.
- **Judging:** greps of UE and gNB log phrases, core NF logs and metrics, SBI queries (JSON parsed, never grepped), eUPF maps, ping/iperf3 to the DN, and tcpdump.
- **Coverage:** 23 gates start a UERANSIM gNB, holding 1,633 rows of `phase-2-final`. sipp acts as the soft IMS UE over UERANSIM's `ims` sessions.
- **The UE host keeps several trees** (`~/UERANSIM`, `-wave28`, `-w27b`, `-w38b`, `-f3`, `-wave21`, `-wave22`): branch sprawl the new simulator should end.
