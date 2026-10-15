# kaluza-sim: architecture (v1, fidelity mode, up to about 100 full-stack UEs)

**Status:** design baseline, 2026-10-14. Requirements are in [`requirements.md`](requirements.md). The SIM, data plane and CLI each have their own document: [`sim-uicc.md`](sim-uicc.md), [`data-plane.md`](data-plane.md), [`cli.md`](cli.md).

## 1. Tenets

1. **Every 3GPP/O-RAN boundary carries encoded bytes.** F1, E1, Xn, NG and the simulated Uu always carry real encoded PDUs, in all-in-one mode too, where they travel over in-memory byte channels. A monolith and a split build therefore cannot drift apart. UERANSIM's split documented "fast paths that bypass the SAP on purpose", which is exactly how that drift starts.
2. **One actor per UE and per RAN UE context.** Each is pinned to one shard thread for its whole life, so protocol code needs no locks.
3. **Independence** ([ADR 0005](adr/0005-independence-from-kaluza-core.md)). The codecs are ours: asn1c output plus table-generated NAS. The oracles are tshark, pycrate and pySim, and OCUDU, Open5GS and free5gc are peers. kaluza-core code is never linked, copied or used to produce an expected value.
4. **The radio is a replicated, deterministic function** of (scene, time, seed). Each node evaluates it locally; no per-packet call goes to a radio server.
5. **Secrets are a type.** `SecretBytes` zeroizes itself and prints only as `<redacted:fpr>`. K and OPc can never reach a log, event, argv, environment variable or pcap.

## 2. Processes and interfaces

```
 ksim-ctl (CLI: KEY=value | --json | events | wait)    ksim-radio (scene: sites, cells, UE paths, seed, edits)
        │ HTTP/JSON + NDJSON events + /metrics                │ snapshot + versioned deltas (each node keeps a replica)
 ┌──────┴───────────────┐   KAIR (sim Uu)   ┌──────────────┴─┐ F1-C SCTP 38472 ┌───────────────┐ NG-C SCTP 38412
 │ ksim-ue  (UE farm)   │◀─────────────────▶│ ksim-du (O-DU) │────────────────▶│ ksim-cucp     │──────────▶ AMF
 │ UeDevice actors:     │  UDP/UNIX/memory  │ cells, SI, RA, │  F1-U GTP-U+NR-U│ (O-CU-CP)     │◀─Xn-C 38422─▶ CU-CP
 │ UICC⇄card, NAS, RRC, │                   │ paging, ideal  │──────┐          └──────┬────────┘
 │ PDCP/SDAP, netns+TUN │                   │ MAC/RLC, RLM   │      │       E1 SCTP 38462
 └──────────┬───────────┘                   └────────────────┘      ▼                 ▼
   APDUs: in-proc | vpcd | PC/SC                              ┌───────────────┐ NG-U GTP-U 2152
                                                              │ ksim-cuup     │──────────▶ UPF (eUPF / UPF-VPP)
                                                              │ (O-CU-UP)     │◀─Xn-U─▶ CU-UP
                                                              └───────────────┘
```

### 2.1 Executables

| Executable | Owns |
|---|---|
| `ksim-ue` | The UE farm. One `UeDevice` actor per UE: persona, UICC terminal, NAS MM/SM/SMS, RRC, PDCP/SDAP, ideal RLC/MAC, a RadioReplica, and a netns with a TUN per PDU session. Soft cards run in-process. |
| `ksim-du` | O-DU. Cells; MIB/SIB1 encoding and SI scheduling; PRACH, RAR and contention resolution; C-RNTI pools; ideal MAC/RLC; paging occasions (PF/PO); radio-link supervision; F1AP-DU; F1-U with NR-U. |
| `ksim-cucp` | O-CU-CP. RRC-CU; PDCP-C for SRB1/SRB2; NGAP; XnAP; F1AP-CU; E1AP-CP; mobility manager; AS-security manager; sharded UE context store; inactivity supervision; AMF selection (NNSF). |
| `ksim-cuup` | O-CU-UP. E1AP-UP; SDAP; PDCP-U; GTP-U endpoints (NG-U, F1-U, Xn-U); NR-U flow control; handover forwarding and reordering buffers. |
| `ksim-radio` | Scene authority. Sites, cells, UE positions and mobility models, model parameters, the run epoch. It applies control edits (move, blackout, pathloss) and publishes them as versioned deltas. |
| `ksim` | All-in-one. Any subset of the roles above in one process. F1, E1, Xn and the air link use in-memory byte channels (or `--loopback-sctp`); NG-C and NG-U are always real sockets. |
| `ksim-ctl` | CLI over every node's control API ([`cli.md`](cli.md)). |
| `ksim-sim` | Offline card lifecycle: validate, import/export, serve over vpcd, derive range keys, provision the 001/01 range through the core's UDR provisioning API and write the 999/70 seed file ([ADR 0008](adr/0008-subscriber-provisioning-api.md)), burn a real card over PC/SC ([`sim-uicc.md`](sim-uicc.md)). |
| `ksim-netd` | Optional privileged helper. It creates the netns and TUN devices and hands the file descriptors over SCM_RIGHTS, so the farm can run unprivileged. |

### 2.2 Interfaces

| Link | Protocol | Transport | Default |
|---|---|---|---|
| UE farm ↔ DU | KAIR v1 (§2.3) | UDP; UNIX SOCK_SEQPACKET on one host; memory in all-in-one | DU on 41000 + DU index |
| DU ↔ CU-CP (F1-C) | F1AP TS 38.473 j40, APER | SCTP, DU is the client | 38472, PPID 62 |
| DU ↔ CU-UP (F1-U) | GTP-U TS 29.281 with NR-U TS 38.425 | UDP | 2152 |
| CU-UP ↔ CU-CP (E1) | E1AP TS 37.483 j40 | SCTP, CU-CP listens | 38462, PPID 64 |
| CU-CP ↔ AMF (NG-C) | NGAP TS 38.413 j40 | SCTP with SCTP_NODELAY | 172.30.30.1:38412, PPID 60 |
| CU-UP ↔ UPF (NG-U) | GTP-U with the PDU Session Container TS 38.415 | UDP, bound to an explicit address | 2152 |
| CU-CP ↔ CU-CP (Xn-C) | XnAP TS 38.423 j40 | SCTP; both sides listen, the lower global gNB ID connects | 38422, PPID 61 |
| CU-UP ↔ CU-UP (Xn-U) | GTP-U with NR-U; PDCP SN carried for AM DRBs | UDP | 2152 |
| Nodes ↔ `ksim-radio` | Scene snapshot plus NDJSON deltas | HTTP over the run's UNIX socket; TCP in all-in-one | 9405 (all-in-one) |
| `ksim-ctl` ↔ nodes | HTTP/JSON, NDJSON events, `/metrics` | UNIX socket per node under `/run/ksim/<run>/` (split mode, per-node netns); TCP on loopback in all-in-one | 9400–9405 (all-in-one) |
| Terminal ↔ card | APDUs (ETSI TS 102 221 / TS 31.102) | in-process, vpcd TCP 35963+n, or PC/SC | — |
| Taps | GSMTAP-SIM on UDP 4729; Exported-PDU on UDP 4730 (kaluza-ue's live format) | UDP | — |

Lab addresses on VLAN 30: kaluza-sim uses **172.30.30.30–.39** on kaluza-uesim, one ipvlan netns per RAN node, clear of UERANSIM and n3iwue at .20–.23. F1 and E1 between the nodes of one gNB run on a host-internal bridge. In split mode, control APIs are UNIX sockets under `/run/ksim/<run>/`. Details: [`lab.md`](lab.md).

### 2.3 KAIR v1: the simulated Uu link

The header is 32 bytes, in network byte order:
```
0  u16 magic 0x4B41 'KA' | 2 u8 version=1 | 3 u8 frame type | 4 u16 flags | 6 u16 payload length
8  u32 cell_handle   (DU-assigned; announced together with NCI/PCI/ARFCN)
12 u32 radio_id      (farm-assigned UE handle, used for addressing only)
16 u64 tx_time_ns    (sender's CLOCK_REALTIME)
24 u32 sfn_slot      (stamped by the DU as SFN<<8|slot)
28 u16 rnti | 30 u16 seq (per link and direction)
32 TLVs {u8 type, u16 len, value}: SDU{lcid, rlc_mode, bytes}, MAC_CE{...}, SCENE{version}
```

**Frame types:**
- Setup and broadcast: `CELL_ANNOUNCE`, `SUBSCRIBE`, `BCH` (the MIB), `SI` (SIB1 and SI messages), `PCCH` (a Paging message stamped with the PF SFN and i_s, plus an SI-change flag).
- Random access:
  - `PRACH`: preamble and occasion, with RA-RNTI = 1 + s_id + 14·t_id + 14·80·f_id + 14·80·8·ul_carrier_id.
  - `RAR`: TC-RNTI, backoff and TA.
  - `MSG3`: a UL-CCCH/CCCH1 SDU, or a C-RNTI MAC CE plus DCCH.
  - `MSG4`: the contention-resolution identity (the first 48 bits of the CCCH SDU) plus a DL-CCCH SDU.
- Data and housekeeping: `DL_SDU` / `UL_SDU` (per-LCID RLC SDUs, several per datagram), `MAC_CE`, `KEEPALIVE`.

**Behaviour:**
- **Broadcast and paging** go once per subscribed farm shard per cell. The farm delivers them to UEs whose RadioReplica says the cell is decodable.
- **Random access is real.** UEs that pick the same preamble in the same occasion all get the RAR. The DU decodes the strongest Msg3, and the others fail contention resolution and back off. Handover uses contention-free RA with dedicated preambles.
- **Addressing.** `radio_id` locates a UE; it never identifies it. DU protocol state is keyed only by RNTI, and a lint test enforces this.
- **Impairments respect the RLC mode.** Delay, loss and jitter are applied at the receiving ideal MAC, per link. On an AM bearer, loss turns into ARQ delay. On UM or TM the SDU is dropped. An SRB SDU never silently vanishes.
- **Radio model:**
  - `ksim-radio` owns the scene. Each DU and farm keeps a RadioReplica.
  - The DU uses it for uplink coverage and RLF supervision.
  - The farm uses it for SI decodability, RSRP/RSRQ/SINR measurements, Qin/Qout and cell selection.
  - Frames carry the scene version, and a mismatch raises an event.

**Phase-2 seam.** PDCP and RRC only ever see `entity/rlc/IRlcBearer` and `entity/mac/IMacSap`.
- v1 binds `IdealRlc` and `IdealMac`. Phase 2 binds TS 38.322 TM/UM/AM and TS 38.321 MAC with a DU scheduler.
- KAIR v2 adds `TB_DL`, `TB_UL`, `UCI` and `PRACH_IND` frames keyed by (SFN, slot, HARQ id, RNTI). They are deliberately shaped like FAPI P7, so a later bridge into OCUDU's split-6 plugin seam is translation, not redesign.
- `platform/SlotClock` exists in v1, but nothing subscribes to it yet.

## 3. Code layering and repo layout

```
kaluza-sim/
  CMakeLists.txt CMakePresets.json REUSE.toml NOTICE LICENSES/
  spec/            pinned inputs, never hand-edited
    INDEX.tsv      doc, version, sha256, what is derived from it
    3gpp/<series>/ fetched zips (gitignored)      asn1/{rrc,ngap,f1ap,e1ap,xnap}/*.asn (extracted, committed)
    nas/{24501,24008,24011,23038}/*.tsv           kat/*.tsv (MILENAGE, TUAK, MILENAGE-256, EEA/EIA, UEA2/UIA2, ECIES C.4, EAP-AKA')
    v1-pdus.tsv    every v1 PDU type, derived (the P0 exit denominator)
    tools/ docx_asn1.py docx_tables.py kat_extract.py fetch.py verify_index.py   (manifest.tsv lists the pinned documents)
  third_party/     asn1c runtime (BSD-2) · OCUDU SNOW3G/ZUC kernels (BSD, NOTICE) · PacketRusher eBPF (Apache-2.0, later)
  cmake/           asn1c.cmake (codegen + stamps) · layers.cmake · sanitizers.cmake · fuzz.cmake
  src/
    platform/  reactor shard mpsc timer_wheel clock rng log config metrics pcap(pcapng, exported-pdu, gsmtap) buf secret slotclock
               executor sim_loop coro event mutation transport memlink   (P1, ADR 0009)
    net/       sctp (kernel UAPI) udp (mmsg) tcp tun netns netlink netd
    crypto/    milenage tuak milenage256 kdf keys5g nea nia ecies eap_aka_prime
    codec/     asn1/ (wrappers; msg/ typed builders) nas/ (+ sms, ie/) uicc/ (apdu, fcp) up/ (gtpu, PSC and NR-U frames) pdcp/ sdap/ air/
    entity/    pdcp/ sdap/ gtpu/ nru/ rlc/{iface,ideal} mac/{iface,ideal}
    uicc/      os/ fs/ usim/ isim(Ph2)/ image/ terminal/ transport/{inproc,vpcd,pcsc} trace/ secrets/
    radio/     scene/ mobility/ pathloss38901/ shadowing/ measure/ rlm/ capacity/ replica/
    proc/      ue/{nas_mm,nas_sm,nas_sec,sms,rrc,idle,meas,plmn}
               ran/{rrc_cu,ngap,xnap,f1ap_cu,f1ap_du,e1ap_cp,e1ap_up,mobility,paging,ra,si,security}
    node/      ue/ du/ cucp/ cuup/ radio/ aio/
    api/       openapi.yaml events.tsv http/ ndjson/
  apps/        ksim-ue ksim-du ksim-cucp ksim-cuup ksim-radio ksim ksim-ctl ksim-sim ksim-netd
  personas/ cards/ topologies/
  tests/       unit/ corestub/ procedure/ component/ fuzz/ vectors/ oracles/{tshark,pycrate,pysim}
  gates/       lib/ksim.sh verification/*.sh rows/p1.tsv allow/open5gs.tsv cores/*.env   (POSIX sh, kaluza-core style)
  tools/       ci.sh guards/check_*.py persona_extract.py kair.lua crosswalk.py provenance.py p1_exit.py
  docs/        this documentation · adr/ · compliance/ (from P0) · findings/ · abstraction-ledger.md
```

**Dependency rules** (kaluza-core's rule 4, "codecs hold no state", carried over):
- **R1:** `platform` depends on nothing else in the tree.
- **R2:** `crypto` is pure functions over OpenSSL and the vendored kernels.
- **R3:** `codec` is pure functions: `decode(span) -> Result<T>` and `encode(const T&, Writer&)`. No sockets, timers, logging, crypto or globals. The NAS security header is parsed here; MAC and ciphering are computed elsewhere.
- **R4:** `entity` objects are passive. Time comes from an injected `TimerService` and I/O goes through injected notifiers. No threads, no sockets.
- **R5:** `uicc/os` knows nothing of UEs, and `uicc/terminal` knows nothing of NAS.
- **R6:** `proc` is single-threaded per actor and never blocks. It sends only through ports (`INgapTx`, `IF1Tx`, …).
- **R7:** only `net` and `node` call socket, epoll, ioctl or setns. The one exception is the epoll calls inside `platform`'s reactor, which is the event loop they all run on.
- **R8:** `radio` is pure.

The rules are enforced by PRIVATE CMake link graphs plus `tools/guards/check_layers.py`, the counterpart of kaluza-core's Maven enforcer.

**As built** (P0 put the codecs under four directories, not one per protocol): `codec/asn1`, `codec/nas` (5GMM, 5GSM, SMS), `codec/uicc` (APDU, AUTHENTICATE, BER-TLV, FCP) and `codec/up` (GTP-U, PSC, NR-U). Two consequences of the rules for P1:
- the vpcd transport splits in two: its framing is `uicc/transport/vpcd`, and its TCP socket is `net/tcp`, wired together in `apps/ksim-sim` (R7);
- `codec` cannot hold `SecretBytes`, so the layouts of EF 4F03 and 4F05, which carry keys, are coded in `proc/ue/nas_sec/persist`.
- P1 N6 added `codec/air` (KAIR v1), `codec/pdcp`, `codec/sdap` and `codec/asn1/msg/rrc`. The RRC builders build each value as X.697 JSON and let the generated code encode it (strict UPER), so the ASN.1 constraints are applied by the code that decodes (row KS-RRC-B2). `entity/` holds `pdcp`, `sdap`, `rlc/{iface,ideal}` and `mac/{iface,ue_ideal}`.
- P1 N7 added `codec/asn1/msg/{ngap,f1ap}` (the same JER route, with `peek()` for the TS 38.413 §10 handling) and `proc/ran/{du,cucp}`. The DU holds the network side of the ideal MAC itself; both take their F1 and NG-C associations as `IAssoc`, so memlink and SCTP serve alike. The gNB ID layout `[shard:4][gen:4][index:24]` is kept with shard and generation 0 (one shard in P1); the `node/` binders and the SCTP I/O thread come with `ksim` in N8.
- P1 N8 added `node/ue/device` (one UE: card, terminal, RRC, 5GMM) and `node/aio` (topology, run directory, captures with NGAP keys zeroed, the dev-PC guard, the all-in-one node and its control routes), `api/` (the reply model, `wait`, the cpp-httplib server; `openapi.yaml` documents the routes) and the apps `ksim`, `ksim-ctl`, `ksim-corestub` and `ksim-sim` (`range init|derive|provision|deprovision`). The all-in-one node runs on one shard, NG-C's SCTP association on its reactor; the SCTP I/O thread and the ID routing still wait for a second shard. cpp-httplib's sockets sit in `api/` on the control threads (row KS-PLAT-B20).
- P1 N9 added `net/{netlink,netns,netd}` and `apps/ksim-netd`, the root helper (row KS-PLAT-B22). `SctpClient` takes a `SocketSource`, so the CU-CP's NG-C sockets come from netd, made in the node's namespace. `ksim-sim range provision --target kaluza` is the UDR API client (row KS-UICC-B4).
- P1 N10 added `codec/asn1/msg/e1ap` and the session IEs of NGAP and F1AP (row KS-E1AP-B1), `codec/ip` (IPv4 and ICMP echo for the inject-mode ping and the stub's DN reflector), `entity/gtpu` (the GTP-U endpoint, row KS-GTPU-B2), `proc/ran/cuup` (row KS-E1AP-B2), the session procedures of `proc/ran/cucp` and the DRBs of `proc/ran/du` (rows KS-NGAP-B5, KS-F1AP-B2), and `proc/ue/nas_sm` (row KS-SM-B1), carried by 5GMM's NAS transport. The roles `e1ap_cp`/`e1ap_up` of the tree above live in `cucp` and `cuup`, and NR-U is framed by `codec/up` inside `entity/gtpu` (no `entity/nru`). The all-in-one node runs the CU-UP beside the CU-CP and the DU: E1 over memlink, F1-U over memlink datagrams, N3 on a real UDP socket from the CU-UP's namespace (row KS-PLAT-B24). The core stub gained its SMF and UPF (row KS-SM-B2).
- P1 N11 added `net/tun` (a TUN descriptor on the reactor behind `IPacketPort`), netd's UE operations (row KS-PLAT-B25) and `node/ue/dataplane` (`IUeNet`, netd's implementation), so a UE device has a namespace and a TUN per session (row KS-PLAT-B26). The farm's per-namespace rtnetlink socket of section 6 is netd's: ksim stays unprivileged and asks for each change.
- P1 N12 added `proc/ue/nas_sec/persist` (EF 4F01, 4F03 and 4F05, row KS-UICC-B7) and completed `proc/ue/nas_mm` (5GMM-IDLE, the service request, paging, periodic and mobility registration, network de-registration, the reject causes and their lists; row KS-NAS-B5). Radio link supervision runs over the ideal link (ledger A-14): the UE's RRC and the DU each watch for the other going quiet. `node/aio` builds the gNB's nodes separately from the system's side (netd's namespaces, the N3 socket, the air), so `gnb restart` rebuilds them in place; `ksim-corestub` keeps its AMF, and so the UE contexts, across a new association (row KS-NGAP-B6). The N12 follow-up added `codec/nas/eap` (EAP packets and the EAP-AKA' attributes; AT_MAC is computed in `proc`, which holds K_aut) for EAP-AKA' (row KS-NAS-B6).
- P1 N13 added `proc/ue/sms` (CM, RL and TL of the MS over 5GMM's NAS transport, row KS-SMS-B2) and the core stub's SMSF (`tests/corestub/smsf`, row KS-SMS-B3).
- P1 N14 added `uicc/transport/vpcd` (the framing; the card side behind pcscd's vpcd driver, the terminal side over a stream a card connected) and `uicc/trace` (APDU-level GSMTAP-SIM records with redaction, row KS-UICC-B9). `node/ue/device` puts a `TracingTransport` between the reader and the terminal, and `node/aio`'s capture writes `sim.pcapng`. `apps/ksim-sim` has serve, validate, export and import (row KS-UICC-B10), the TCP socket from `net/tcp`.

## 4. Codec pipelines

### 4.1 ASN.1 (RRC UPER; NGAP, F1AP, E1AP, XnAP APER)
- **Extraction.** Our own clean-room `spec/tools/docx_asn1.py` extracts the ASN.1 between the `-- ASN1START` / `-- ASN1STOP` markers of the Rel-19 docx.
  - It has unit tests for the docx traps: `<w:tab/>` appears as a sibling of `<w:t>`, and `<w:br/>` is a real newline.
  - For RRC it takes `NR-RRC-Definitions` **and** `NR-InterNodeDefinitions`. The latter holds HandoverPreparationInformation, HandoverCommand, CG-ConfigInfo and UERadioPagingInformation, which the handover containers need.
  - The output is committed and byte-stable, next to the sha256 of the source docx.
- **Compiler.** **asn1c, the mouse07410 fork at commit 18e56503** (2024-08-21; BSD-2). The fork's HEAD (2025/26) aborts on the parameterized `ProtocolIE-Container` family, and stock 0.9.29 cannot parse Rel-16+ `[[ ]]` CHOICE brackets. These are facts from the UERANSIM fork's notes; only the facts are taken.
  - Flags: `-fcompound-names -findirect-choice -fno-include-deps -pdu=all -no-gen-OER -no-gen-BER -no-gen-XER -no-gen-random-fill -no-gen-example -fprefix=<PROTO>_`. That keeps UPER, APER, print and **JER**: JER is always generated, for the oracle comparison and the `ksim-codec` dump.
  - **Built from source** by `tools/build-asn1c.sh` with gcc 15 and `-std=gnu17 -O2 -fno-strict-aliasing`. Without that last flag the fixer segfaults on strict-aliasing UB, failing 33 of the fork's own 130 compiler tests; with it, all 130 pass (row KS-PLAT-T6).
  - **One prefix per protocol** (`-fprefix`, complete at this commit) keeps five protocols in one binary without symbol clashes. A CI `nm` check guards it.
  - **The runtime is vendored unmodified** (`third_party/asn1c/runtime`) and built once. It comes from the skeleton subset asn1c lists for these flags; the BER-only files are not built.
  - **One forced-include config header,** `src/codec/asn1/ksim_asn1_config.h`, fixes the `ASN_DISABLE_*` set for every translation unit. The runtime's structures change layout with it, and with it the `encoding_constraints` initializers need no post-processing (rows KS-PLAT-B3 to B6).
  - **Two recorded renames after generation** (`spec/tools/asn1_gen.py`, logged per stamp in `postprocess.log`):
    - a C enumerator that collides with its own typedef (RRC's `CA-BandwidthClassNR-r17` value `t`; row KS-RRC-B1);
    - the six inner `…__Member` typedef names `-fprefix` leaves bare (row KS-PLAT-B8).

    After these, all 8,110 generated headers of the five protocols compile together in one C++20 translation unit, so code may combine protocols freely.
- **Build.** One shared runtime library and **one static library per protocol**.
  - Generation is keyed by a stamp: sha256 of (.asn, asn1c binary, flags, prefix, config header, generator version). It runs once per stamp, in parallel across protocols, into a shared cache (`~/.cache/kaluza-sim/asn1-gen`), and writes a `files.cmake` manifest from asn1c's own `Makefile.am.libasncodec`, so there is no GLOB and no stale-file-list trap. A stamp miss costs about 4.5 min, mostly F1AP's fixer; a hit costs nothing (row KS-PLAT-T8).
  - Generated C is built with `-O1 -g0 -ffunction-sections`, in unity batches where symbols allow, linked with `--gc-sections`, and cached by stamp in CI.
- **Access rule.** Hand-written code never names a container type whose name encodes a line number:
  ```cpp
  using IeT = std::remove_pointer_t<decltype(m->protocolIEs.list.array[0])>;  // deduced, never spelled
  IeT& ie = asn::push_ie(m->protocolIEs);
  ```
  CI fails if `_[0-9]+P[0-9]+` appears outside the generated directories. `asn::Owned<T>` is the RAII wrapper, and a deep copy is a re-encode.
- **Per-peer release cap.** `peer_release: 18` (for OCUDU) suppresses Rel-19-only IEs towards an older peer, honouring criticality.

### 4.2 NAS (TS 24.501 j80, with 24.007 j50 and 24.008 j50)
- Our own `spec/tools/docx_tables.py` extracts these into TSVs:
  - the message tables of clauses 8.2 and 8.3;
  - the IE references;
  - the 5GMM and 5GSM cause annexes;
  - the TS 24.008 §10.5.6.3A ePCO container IDs.
- `tools/nasgen` turns the TSVs into C++ structs whose decoders follow TS 24.007 §11: the imperative and non-imperative parts, unknown IEIs (ignored, §11.2.4), duplicate IEs, syntactic versus semantic errors (24.501 §7.5–7.8).
- IE codecs are hand-written per §9.11.x. A CI-checked `ie_types.tsv` maps every referenced clause to a codec.
- The user's own `/home/amadeus/Development/ran/kaluza-ue/tools/gen-nas-tables.py` (24.501 v19.7.0, Kotlin side) may be studied. kaluza-core's NAS code and tables may not ([ADR 0005](adr/0005-independence-from-kaluza-core.md)).

## 5. Concurrency and time

- **Shards.** A shard is one thread with:
  - an epoll reactor;
  - an eventfd-woken bounded MPSC inbox;
  - a hierarchical timer wheel at 1 ms resolution, driven by a tickless timerfd. Timer handles carry a generation, so a cancelled timer can't fire late.

  Actors stay on their shard for life: `UeDevice` in the farm, RAN UE contexts in each node, each node's management actor on shard 0. Shards talk only by message, and packet buffers move with ownership.
- **SCTP dispatch.** One I/O thread per node owns every SCTP descriptor. They are one-to-one sockets, so faults are easy to aim, and the kernel UAPI (`SCTP_SOCKOPT_BINDX_ADD`/`CONNECTX`) avoids depending on libsctp.
  - The I/O thread reads each (association, stream) in order and decodes. At 100 UEs a full APER decode is cheap.
  - It then routes:
    - a UE-associated message carrying one of our own IDs goes to the shard encoded in that ID's top bits, `[shard:4][generation:4][index:24]`, for RAN UE NGAP, gNB-CU UE F1AP, CU-CP E1AP and XnAP IDs;
    - the first message of a new context goes to a shard chosen by hash;
    - non-UE-associated messages go to the management actor.
  - FIFO queues preserve per-UE order, and the I/O thread never runs procedure code. This is the lesson of kaluza-core's `N2Engine` ordered dispatch: hop off the I/O thread *and* keep per-peer order.
  - Outbound, each UE keeps one stream for its whole context, and stream 0 carries non-UE signalling. Stream IDs are bounded by the negotiated `sac_outbound_streams`, never the requested count.
- **Everything is asynchronous and nothing re-enters.** APDUs, SCTP sends and netns operations complete through the inbox. PC/SC calls and image fsyncs run on a 2-thread blocking pool.
- **How procedures are written.** Normative states (5GMM, 5GSM, RRC, CM) are explicit FSM tables, so they can be printed and tested. Multi-interface RAN orchestration (E1 → F1 → RRC → NGAP) uses C++20 coroutines owned by the UE context. They are cancelled when the context dies, with timeouts on the wheel.
- **Time modes:**
  - **Real time** is the default and is required against a real core. Timers run on CLOCK_MONOTONIC; SFN and mobility run on a CLOCK_REALTIME epoch, with hosts kept in sync by chrony. The ideal link adds 1 ms per hop plus seeded jitter, so no race is won at an impossible zero latency.
  - **Virtual time:** a discrete-event scheduler runs all-in-one against a scripted core stub, so hours of NAS timers pass in milliseconds. It is for procedure tests only.
- **Determinism.** A counter-based RNG keyed by (root seed, node, UE, purpose, counter), so results don't depend on scheduling order. Every run header records the seed, the scenario hash and the build ID. `--insecure-deterministic-crypto` exists for tests only and refuses a non-loopback AMF.
- **Watchdog.** A loop-lag metric plus a `platform.loop_lag` event. Gates ABORT rather than FAIL when lag exceeds the threshold.
- **Thread budget for 100 UEs:** farm 7, DU 4, CU-CP 5, CU-UP 5, radio 2, so about 23 in split mode and about 10 all-in-one. UERANSIM needs 600–800 for the same UEs.

## 6. Inside the UE

```
UeDevice (one actor, pinned to a shard)
 ├ Me: Persona, MeNvm (state/<imei>.yaml: configured/allowed NSSAI, equivalent PLMNs, timer values)
 ├ UiccTerminal ─IApduTransport─▶ SoftCard | vpcd | PC/SC          (sim-uicc.md)
 ├ Nas: Mm (5GMM) · Sm (5GSM per PSI/PTI) · Sms (CP/RP/TPDU) · Sec (NAS security context)
 ├ Rrc: Connected FSM · Idle (PLMN TS 23.122, cell selection TS 38.304, paging DRX) · Meas (L3 filter, A1–A5)
 ├ L2: Pdcp[SRB1, SRB2, DRBn] · Sdap[PSI] · IdealRlc/IdealMac
 ├ RadioView (RadioReplica): RSRP/RSRQ/SINR, Qin/Qout
 ├ DataPlane: netns ksim-ue-<n> · TUN pdu<psi> · uplink classifier · IUeDataPath   (data-plane.md)
 └ AtPort (v1.x, optional): TS 27.007/27.005 on a pty                              (cli.md §5)
```

- **5GMM:**
  - states and substates per TS 24.501 §5.1.3.2, with update status 5U1–5U3;
  - attempt counter and timers T3510, T3511, T3502, T3512, T3517, T3521, T3346;
  - reject causes drive EF.FPLMN and the forbidden TA lists;
  - registration: initial, mobility (on a TAI outside the list) and periodic;
  - service request, with UL data status and PDU session status;
  - deregistration: UE-initiated (normal or switch-off) and network-initiated, where "re-registration required" is followed by a fresh initial registration.
- **Authentication:**
  - **5G AKA:** check the AMF separation bit (#26 if wrong); a MAC failure gives #20; a synch failure gives #21 with AUTS.
  - **EAP-AKA′:** RFC 9048. CK′/IK′ are derived with FC 0x20; K_AUSF = EMSK[0..255].
  - **SUCI:** computed by the ME or by the card, depending on UST services 124 and 125.
  - **Key-trap KATs:**
    - K_AMF's input is the SUPI digits, not the `imsi-` SBI spelling;
    - null-scheme SUCI output is the MSIN digits;
    - K_gNB takes the correct uplink NAS COUNT.
- **5GSM:**
  - per-PSI state machines with T3580, T3581 and T3582;
  - back-off (T3396, T3584, T3585) per (DNN, S-NSSAI), including cause #29;
  - QoS rules and flow descriptions, network-requested modification, reflective QoS;
  - ePCO: DNS (0x000D), MTU (0x0010); the P-CSCF entry comes in phase 2.
- **SMS:**
  - the "SMS requested" bit in the 5GS update type;
  - CP layer per TS 24.011 §5 with TC1\*; RP layer with TR1M/TR2M;
  - TPDUs per TS 23.040, alphabets per TS 23.038;
  - payload container type SMS in UL/DL NAS TRANSPORT.
- **RRC:**
  - setup with T300;
  - AS security mode: SecurityModeComplete is integrity-protected but not ciphered, and ciphering starts afterwards;
  - reconfiguration, including reconfigurationWithSync (T304, contention-free RA), release and re-establishment (T311, T301);
  - capability enquiry, answered from the persona;
  - measConfig with L3 filtering, events A1–A5 and periodic reports, time-to-trigger and hysteresis;
  - RLF by N310, N311 and T310.
- **Idle mode:**
  - **PLMN selection:** automatic or manual, from EF.PLMNwAcT, OPLMNwACT, HPPLMN, EHPLMN and FPLMN.
  - **Cell selection and reselection:** Srxlev and Squal; R_s and R_n ranking; priorities and Treselection, from SIB1–SIB4.
  - **UAC:** basic.
  - **Paging occasions:** UE_ID = 5G-S-TMSI mod 1024, and T = min(negotiated DRX, default DRX). The PO is checked against the DU's SFN stamp.
- **State persistence:** at deregistration or power-off the UE writes to the card, following the TS 24.501 §4.4.2 and TS 31.102 storage and invalidation rules:
  - EF.5GS3GPPLOCI (4F01): 5G-GUTI, last registered TAI, update status;
  - EF.5GS3GPPNSC (4F03): ngKSI, K_AMF, NAS COUNTs, algorithms;
  - EF.5GAUTHKEYS (4F05): K_AUSF, K_SEAF.

  Power-on reads them back, so the UE registers with its 5G-GUTI and a protected initial message. Power-off has three modes: switch-off deregistration, graceful, and abrupt (no card write).
- **Personas** are YAML files holding:
  - IMEISV;
  - 5GMM capability, UE security capability, S1 UE network capability;
  - the UE-CapabilityRAT-ContainerList as raw UPER, plus structured patches;
  - requested DRX, NSSAI, UE usage setting, IP type, the ePCO items requested;
  - `quirks`.

  `tools/persona_extract.py` builds them from:
  - the kaluza-ue Exported-PDU captures (S22+, OnePlus 9 Pro);
  - RRC containers in OCUDU F1AP pcaps;
  - N2 pcaps taken on NEA0 (RM520N, RG255C RedCap).

  The two Quectel personas also draw on the AT manuals and the firmware study ([research/quectel.md](research/quectel.md)). Captures are anonymised before they become fixtures: IMSI and IMEI are rewritten, inside RRC `dedicatedInfoNAS` too.

## 7. Inside the RAN nodes

### 7.1 Components

**CU-CP:**
- `RrcCu`; `PdcpC`.
- `NgapRan`, which covers:
  - NG Setup, configuration updates, NG Reset, Error Indication, Overload;
  - PDU Session Resource Setup/Modify/Release/Notify;
  - Initial Context Setup; UE Context Release Request/Command/Modification;
  - UE Radio Capability Info Indication;
  - handover preparation, allocation, notify and cancel; Path Switch; UL/DL RAN Status Transfer.
- `XnapNode`; `F1apCu`; `E1apCp`.
- `MobilityManager`:
  - A3/A5 policy, with the neighbour table taken from the topology;
  - it classifies each handover as intra-CU, Xn or N2;
  - a control-API override; phase 2 adds an E2 RC override.
- `AsSecurity`; a sharded `UeContextStore`; `Nnsf` (AMF selection by GUAMI or S-NSSAI).

**CU-UP:**
- `E1apUp`.
- `BearerContext`, holding:
  - per PDU session: the NG-U tunnel and SDAP;
  - per DRB: PDCP, the F1-U/NR-U tunnel and the forwarding tunnels.
- `GtpuEndpoint` per local IP: TEIDs carry shard bits; it answers Echo, handles End Marker, and sends Error Indication for an unknown TEID.
- `HoBuffer`: forwarded packets are delivered first, then the new path's packets after the End Marker or a timeout.

**DU:**
- `F1apDu`. F1 Setup carries the served cells and gNB-DU System Information (MIB, SIB1); SIB2–4 arrive from the CU as gNB-CU System Information.
- `Cell`, which owns the SFN clock and the SI scheduler.
- `RaManager`; `RntiPool`; `PagingScheduler` (PF/PO per TS 38.304 §7.1).
- `IdealMac`; `IdealRlc`; `RadioLinkSupervisor`.
- `F1uEndpoint`: NR-U DL DATA DELIVERY STATUS with the highest delivered PDCP SN and the desired buffer size.

### 7.2 Radio loss, inactivity, GBR notification
- **Radio-link failure:** Qout for a set time with no uplink. The DU sends F1AP UE CONTEXT RELEASE REQUEST, and the CU-CP then sends NGAP UE CONTEXT RELEASE REQUEST with cause *radio-connection-with-ue-lost* (TS 38.413 §8.3.2). This closes UERANSIM's gap L1.
- **Inactivity:** the CU-UP sends an E1 inactivity notification, the CU-CP's timer expires (default 15 s, as in OCUDU's config), and the CU-CP requests a release with cause *user-inactivity*.
- **GBR notification:** when the radio model's capacity falls below a flow's GFBR and notification control was requested, the CU-CP sends PDU SESSION RESOURCE NOTIFY.

### 7.3 Xn handover
1. **Decision and keys.** An A3 MeasurementReport reaches the source CU-CP, which decides to hand over. It computes **K_NG-RAN\*** (TS 33.501 A.11, FC 0x70) from the target PCI and SSB ARFCN, using an unused NH if it has one and K_gNB otherwise.
2. **Handover Request.** The source sends XnAP HANDOVER REQUEST with the AS security information {K_NG-RAN\*, NCC}, the UL NG-U TEIDs and HandoverPreparationInformation.
3. **Target preparation.** The target CU-CP:
   - sets up the bearer context on its CU-UP with E1 BEARER CONTEXT SETUP (UP keys, DL forwarding tunnels);
   - sets up the UE context on its DU with F1 UE CONTEXT SETUP (new C-RNTI, CFRA preamble, CellGroupConfig);
   - builds an RRCReconfiguration with sync as the HandoverCommand;
   - returns HANDOVER REQUEST ACKNOWLEDGE with the Xn-U forwarding TEIDs.
4. **Source execution.** The source sends, in parallel:
   - E1 BEARER CONTEXT MODIFICATION to its CU-UP (forwarding tunnels, PDCP SN status request);
   - F1 UE CONTEXT MODIFICATION to its DU (RRC container, transmission stopped). The DU delivers the command.
5. **SN status and forwarding.** The source sends **SN STATUS TRANSFER** (DL: the next COUNT to assign; UL: the first missing COUNT plus a bitmap). The target CU-CP seeds its CU-UP's TX_NEXT and RX_DELIV through an E1 modification. Meanwhile the source forwards DL SDUs over Xn-U.
6. **UE arrival.** The UE runs T304, sends a CFRA PRACH on the target cell, then sends RRCReconfigurationComplete, plus a PDCP status report if one was required.
7. **Path switch and release.**
   - The target CU-CP sends **PATH SWITCH REQUEST**, with the UE's real security capabilities.
   - The UPF's End Marker reaches the target through the source. The target delivers forwarded data before new-path data.
   - The target stores {NH, NCC} from PATH SWITCH REQUEST ACKNOWLEDGE.
   - It sends XnAP UE CONTEXT RELEASE, and the source frees its F1 and E1 contexts.

### 7.4 N2 handover
1. **Required.** The source sends HANDOVER REQUIRED: intra5gs, target global gNB ID and TAI, direct-forwarding availability, a Source-to-Target container.
2. **Target allocation.** The AMF sends HANDOVER REQUEST to the target with {NH, NCC}. The target derives K_gNB vertically from NH, sets up E1 and F1, and acknowledges with the DL and indirect-forwarding TEIDs and the HandoverCommand.
3. **Command and status transfer.**
   - The AMF sends HANDOVER COMMAND to the source.
   - The source sends the RRCReconfiguration to the UE and UPLINK RAN STATUS TRANSFER to the AMF.
   - The AMF relays DOWNLINK RAN STATUS TRANSFER to the target.
   - The source forwards data to the UPF's indirect tunnel.
4. **Completion.** When the UE arrives, the target sends HANDOVER NOTIFY. The AMF then sends UE CONTEXT RELEASE COMMAND (successful handover) to the source.
5. **Failure paths:** cancel, preparation failure and handover failure are covered. T304 expiry leads to re-establishment.

**Intra-CU, inter-DU handover** uses F1 only, plus an E1 modification for the new F1-U TEIDs, with an optional horizontal K_gNB\* key change.

### 7.5 AS keys (TS 33.501 Annex A, FC values checked against j70)
- **K_gNB:** the CU-CP takes it from the NGAP Security Key IE. The UE derives its own from K_AMF and the uplink NAS COUNT (A.9, FC 0x6E). A core mismatch therefore shows up as an attributable AS security-mode integrity failure.
- **Algorithm keys** (A.8, FC 0x69): distinguishers N-RRC-enc 0x03 and N-RRC-int 0x04 stay in the CU-CP. N-UP-enc 0x05 and N-UP-int 0x06 go to the CU-UP in E1 Security Information.
- **NH chain:** both sides walk it (A.10, FC 0x6F) up to the NCC in the HandoverCommand. A multi-hop path mixing Xn and N2 (A→B→C→A) proves the chain end to end.
- **K_AMF′** for AMF relocation follows A.13 (FC 0x72).
- **PDCP re-establishment** follows TS 38.323 §5.1.2. SRBs and UM DRBs reset COUNT; AM DRBs keep it and retransmit unconfirmed SDUs under the new keys. OCUDU's `lib/pdcp/pdcp_entity_tx.cpp` implements the same rule and is a BSD reference.

### 7.6 Seams for phase 2
- **E2:** the metrics registry labels RAN counters with their TS 28.552 names, and each node exposes `ControlHooks` (handover trigger, barring, QoS policy). Prometheus reads the registry in v1. An E2 agent (SCTP PPIDs per O-RAN WG3; KPM, RC, CCC) will read and drive the same objects.
- **O1:** node configuration is a typed tree with change notifications. An O1 NETCONF front end will map GNBCUCPFunction, GNBCUUPFunction, GNBDUFunction, NRCellDU and NRCellCU (TS 28.541) onto it.
- **NRPPa:** the DU and CU-CP keep the radio replica's ground-truth geometry, so NRPPa answers can be computed from it, AoA included.

## 8. Radio model (`src/radio`, `ksim-radio`)

- **Scene:**
  - sites with antenna height, azimuth and pattern;
  - cells: PCI, NCI, SSB ARFCN, band, TAC, PLMN/NPN lists, Tx power, carrier;
  - UE positions and mobility models: static, waypoints, random waypoint, scripted paths;
  - edits: move, blackout, pathloss and shadowing offsets.
- **Pathloss:** TR 38.901 UMa, UMi and InH, LOS and NLOS. The model choice is a recorded B-row. Shadowing is seeded; fast fading is off in v1 because there is no PHY.
- **Measurements:** SS-RSRP, SS-RSRQ and SS-SINR per (UE, cell) per TS 38.215, plus interference from co-channel cells. The UE applies L3 filtering and event evaluation itself, as a real UE does.
- **RLM:** SINR is mapped to in-sync and out-of-sync with Qin/Qout thresholds (TS 38.133, T0). That drives N310/T310 at the UE and radio-link supervision at the DU.
- **Capacity:** a coarse per-cell capacity model drives GBR notification control and the optional per-link rate cap. Real scheduling arrives with phase 2.

## 9. Control, scenarios, observability

- **API:** HTTP/JSON on each node, described in OpenAPI at `src/api/openapi.yaml`. An NDJSON event stream at `GET /v1/events?follow=1`; Prometheus at `/metrics`. HTTP was chosen over gRPC because sh gates can drive it with curl and Python, and C++ needs no protobuf toolchain. The CLI is in [`cli.md`](cli.md).
- **Events:** every event name is registered in `src/api/events.tsv` with its spec reference, and CI fails on an unregistered name. Procedures emit start, milestone and end events with an instance ID and correlation IDs:
  ```
  {"seq":48211,"ts":"2026-10-14T10:02:03.123456Z","node":"ue-farm-1","ue":"imsi-001010000300017","ev":"nas.reg.accept","spec":"TS 24.501 5.5.1.2.4","proc":"registration#12","f":{"type":"initial","t3512_s":3240},"ids":{"ran_ue_ngap_id":"0x10000003","c_rnti":"0x4601","pci":1}}
  ```
- **Topology and scenario YAML.** One file is the source of both node configuration and the radio scene:
  ```yaml
  plmn: "00101"
  amf: [{addr: 172.30.30.1, port: 38412}]
  gnbs:
    - id: {value: 0x1A0, bits: 22}
      cucp: {ng_bind: 172.30.30.30}
      cuup: [{id: 1, n3: 172.30.30.31}]
      dus: [{id: 1, cells: [{pci: 101, ssb_arfcn: 632256, band: n78, tac: 1, site: s1, azimuth: 0, tx_dbm: 46}]}]
  radio: {model: uma, seed: 42, sites: {s1: [0, 0, 25], s2: [500, 0, 25]}}
  ues:
    - {group: phones, count: 50, persona: personas/s22plus.yaml, card: {template: cards/usim-5g.yaml, range: "001010000300000"},
       mobility: {model: waypoint, path: [[50, 0], [450, 0]], speed_mps: 15},
       sessions: [{dnn: internet, snssai: "1-000001", type: ipv4}]}
  ```
  A scenario timeline adds `at`/`after` actions and `expect` assertions that print KEY=value rows. The pass/fail rows themselves stay in sh gates.
- **Packet captures:**

| Interface | Framing |
|---|---|
| Uu RRC and NAS | DLT 252 Exported-PDU with EXP_PDU_TAG_PROTO_NAME `nr-rrc.{bcch.bch, bcch.dl.sch, pcch, dl.ccch, ul.ccch, ul.ccch1, dl.dcch, ul.dcch}` and `nas-5gs` (plaintext, before ciphering and after deciphering) |
| Uu PDCP | Wireshark's `pdcp-nr` UDP framing. An opt-in export of the pdcp-nr UE keys table lets Wireshark decrypt (AS keys only) |
| F1-C, E1, NG-C, Xn-C | Exported-PDU `f1ap`, `e1ap`, `ngap`, `xnap`, plus kernel tcpdump as evidence |
| F1-U, NG-U, Xn-U | DLT_RAW with synthesized IPv4/UDP, so the `gtp` dissector decodes NR-U and the PDU Session Container natively |
| SIM | GSMTAP-SIM |
| KAIR | `tools/kair.lua` |

  pcapng packet comments carry the SUPI, RNTI and NGAP IDs.
- **Metrics:** `ksim_<node>_<area>_<what>_{total,seconds}`. RAN counters carry a `pm_name` label with the TS 28.552 name.
- **Fault injection:**
  - node: `crash` (the peer sees an ABORT), `stop` (SHUTDOWN), `freeze` (SIGSTOP, so the peer's heartbeat times out);
  - SCTP: `abort`, `blackhole`;
  - radio: cell blackout, move a UE, pathloss and shadowing offsets;
  - message rules, e.g. `uu.ul.rrc==RRCReconfigurationComplete && ue==17 → drop×1`;
  - card: removal, wrong RES or SQN.

  Invariant: `ksim-ctl <node> faults list` prints `FAULTS=0` when clean, and a gate set refuses to start otherwise.
- **Mutation switches** exist only in builds with `KSIM_MUTATIONS=ON`, for example `kamf_input_sbi_spelling`, `null_suci_full_imsi`, `wrong_ncc`, `skip_end_marker_order`. They give gates their must-fail control rows.

## 10. Build and test

- **Presets:** CMake ≥ 3.28 with presets `dev` (gcc 15.2 + ccache + mold), `asan` (ASan + UBSan), `tsan`, `release`, `release-lab` (the kaluza-uesim x86-64-v3 set), `fuzz` (clang 21 + libFuzzer) and `cov`. There is no separate `oracle` preset, since JER is always generated (row KS-PLAT-B5). Every check runs through `tools/ci.sh`.
- **Libraries:** OpenSSL 3, pcsc-lite, yaml-cpp, nlohmann/json, fmt + quill, CLI11, cpp-httplib, GoogleTest; libbpf later. No libsctp.
- **Test layers:** unit (codecs, entities, KATs, card OS) → procedure tests on virtual time, named after spec clauses → component (all-in-one against a scripted core stub) → system gates against kaluza-core, plus an interop matrix ([`verification.md`](verification.md)).
- **Oracles:**
  - asn1c-JER versus a tshark leaf comparison, as `/home/amadeus/Development/ran/kaluza-ue/tools/rrc-oracle.py` already does for RRC;
  - tshark field/offset fixtures, with pcaps fed on stdin because AppArmor blocks paths under `~/Development`;
  - pycrate in a venv;
  - pySim-shell reading every EF of a vpcd-served card.
- **Fuzzing:** libFuzzer on every decoder (NAS plain and protected, every RRC PDU type, NGAP/F1AP/E1AP/XnAP, PDCP, SDAP, GTP-U and extension headers, NR-U, the PDU Session Container, KAIR, APDU and FCP, YAML and JSON inputs). Round-trip properties too, with a nightly run.
- **Guards:**
  - clang-tidy and the layer checker;
  - SPDX headers and REUSE;
  - a provenance scan that denies UERANSIM, OAI and onomondo-uicc text, with a NOTICE for OCUDU and PacketRusher copies;
  - the secret canary.

## 11. Risks (software)

| Risk | Mitigation |
|---|---|
| asn1c volume (about 7–10k translation units with XnAP): RAM and compile time | One library per protocol, `-O1 -g0`, stamp cache plus ccache, unity batches, gc-sections; extract only the RRC modules needed |
| asn1c APER/UPER corner cases in Rel-19 (extensions, open types, large INTEGERs); a known wrong bit width (SRBID) | Round-trip fuzzing; tshark/pycrate cross-decode of every corpus message; a patch queue for the BSD runtime; `-S` rows |
| The pinned 2024 asn1c stops building | Build it in a pinned container; cache generated output by stamp |
| PDCP COUNT/HFN mistakes at handover (UM vs AM rules, SN-status semantics, RX_DELIV after handover) | Spec-row tests on TS 38.323 §5.1.2; randomized loss/reorder properties; a `pdcp_decipher_sanity_fail_total` metric; pdcp-nr pcaps with opt-in keys |
| Key-chain traps (UL NAS COUNT for K_gNB, NH/NCC over several hops, SSB ARFCN in K_NG-RAN\*) | A traps register with KATs; mutation switches; multi-hop handover gates; OCUDU interop |
| SCTP stream counts, multi-homing, NODELAY, a missing kernel module | Bound by the negotiated count; a startup probe with a named error; single-homed by default |
| Time agreement between processes and hosts | The DU stamps SFN on every frame; chrony; single host by default |
| netns privileges and host noise (the P-33 class) | Sysctls set before link-up; devices unmanaged by NetworkManager; `ksim-netd`; a noise metric |
| Event-loop stalls fire T300/T3510 spuriously | Nothing blocks on a shard; a lag watchdog; gates ABORT on lag |
| OCUDU's Rel-18 ASN.1 against our Rel-19 | Per-peer release cap with criticality-aware IE suppression |
| The ideal L2 hides MAC/RLC-dependent behaviour | `docs/abstraction-ledger.md` records every abstraction; the phase-2 seams are fixed now |

The build order is in [`roadmap.md`](roadmap.md).
