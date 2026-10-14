# Research: PacketRusher (local clone, 2026-10-14)

**Clone:** `/home/amadeus/Development/ref/PacketRusher`, HEAD `7836091` (v2.0.0-1, commit dated 2026-10-08), from https://github.com/HewlettPackard/PacketRusher. The user allowed the download.

**Licence: Apache-2.0.** Code may be copied into `third_party/packetrusher/`, keeping its header and adding a NOTICE entry ([ADR 0004](../adr/0004-clean-room-licensing.md)).

## Architecture

- **Language and lineage:** Go 1.26. The module is still named `my5G-RANTester`, the project it was forked from.
- **CLI** (`cmd/packetrusher.go`): `ue`, `gnb`, `multi-ue`, `control`, `run-scenario`, `custom-scenario` (WASM), `amf-load-loop`, `amf-availability`.
- **Packages:** gNB side `internal/control_test_engine/gnb/{context,ngap,nas,gtp}`; UE side `internal/control_test_engine/ue/{context,nas,gtp,state,scenario}`; SUCI in `internal/common/sidf` (null, Profile A, Profile B); a mock 5GC in `test/aio5gc`.
- **Concurrency:** one goroutine per UE with a `select` loop. The UE and gNB talk over **in-process Go channels: no RRC and no radio**. N2 is SCTP via `ishidawataru/sctp`.
- **Scale:** "tested up to 10k UEs" (README); 32,767 UEs per gNB on the shared gtp5g device; BPF maps hold 65,536 entries.
- **Mobility:** multiple gNBs in one process. Xn handover via Path Switch; N2 handover (Required, Request, Command, Notify), timer- or control-triggered.
- **NAS and NGAP:** free5gc `ngap` v1.2.0 (bundled APER) and a patched `free5gc/nas` v1.3.0 (`third_party/free5gc-nas`). 5G AKA with resync, but no EAP-AKA′ path. Up to 15 PDU sessions. CM-IDLE and service request; GUTI re-registration; roaming.

## The data plane

Selected with `--tunnel-backend auto|ebpf|gtp5g|userspace` (`config/config.go`). `auto` tries ebpf, then gtp5g (if the module is loaded), then userspace.

**The eBPF backend** is `internal/control_test_engine/ue/gtp/ebpfgtp/bpf/gtpu.c` (194 lines), loaded by `ebpfgtp.go`, from PR #223 (merged 2026-10-05). It keeps a **TUN per UE** (`gtp0<MSIN>`) and attaches three `SEC("tc")` programs with **TCX**, which needs Linux 6.6 or later:
1. **`uplink`**, on the TUN's egress: looks up `uplinks[ifindex]`, checks the source (the UE's IPv4 address or IPv6 /64), adds an Ethernet header, marks the skb and redirects to the stage.
2. **The stage**, a veth pair `prs<n>a/b` with MTU 65535 and TX checksum offload off, so the kernel splits GSO and fills in checksums.
3. **`encap`**, on the stage's ingress: outer IPv4, UDP 2152 and GTP-U (8 bytes, or 16 with a 0x85 PDU Session Container carrying the QFI). The IPv4 checksum is computed in the program and the UDP checksum is 0. Then `bpf_skb_adjust_room`, `bpf_skb_change_type(PACKET_HOST)` and `bpf_redirect_neigh(n3)`.
4. **`decap`**, on N3's ingress: looks up `downlinks[{local N3 address, TEID}]`, strips the outer headers and calls `bpf_redirect(tun, BPF_F_INGRESS)`. The kernel delivers the packet to sockets bound to the UE's IP.

Unhandled packets return `TC_ACT_UNSPEC` and go to user space: echo, IPv6 RAs, fragments, multi-segment GSO, unknown TEIDs.

XDP was rejected (issue #81): an XDP redirect into a TUN goes to the TUN's reader, not to the kernel stack.

**Per-UE plumbing, shared by all backends:**
- a dummy device `val<MSIN>` holding the UE's /32 address;
- a routing table per UE plus an `ip rule`, or a `vrf<MSIN>` with `--tunnel-vrf`;
- everything sits in the **host network namespace**.

Applications bind to the UE's IP (`iperf3 -B`, `ping -I`) or use `ip vrf exec`.

**Throughput** (README; 16-core host, Linux 7.0, free5GC UPF, iperf3 TCP), UL/DL in Gbit/s:

| Backend | 1 UE | 4 UEs |
|---|---|---|
| ebpf | 3.4 / 4.7 | 10 / 14 |
| gtp5g | 2.9 / 2.8 | 11 / 10.5 |
| userspace | 1.1 / 1.4 | 0.9 / 1.3 |
| userspace `-d` | 1.1 / 1.4 | 3.6 / 6.2 |

## Limits

- No radio layers: no RRC, PDCP, RLC, MAC or PHY.
- One QFI per session; QoS-rule packet filters are not used; only PDU session 1 is tunnelled.
- No SIM abstraction: K/OPc come from YAML, Milenage only.
- No handler for network-initiated deregistration or PDU session modification.
- IPv6 needs the ebpf or userspace backend.
- Host-netns side effects.
- Scenarios are JSON step lists or WASM (TinyGo, "highly WIP").
- Prometheus metrics, but none from the eBPF datapath yet.

## What kaluza-sim takes from it

The **express path** for the later scale mode ([`../data-plane.md`](../data-plane.md) §4): the TCX pattern, the veth stage and the map keys, adapted to:
- a **netns per UE** with a veth and `bpf_redirect_peer`;
- **several QFIs per session**, using an eBPF copy of the UE's QoS rules;
- a user-space fallback for Echo, Error Indication, End Marker, RA and fragments.

The control plane stays at full fidelity.
