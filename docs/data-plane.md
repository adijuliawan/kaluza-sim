# Data plane

**v1 rule:** user data goes through the simulated stack, so the fidelity checks have something to check. That stack is the UE's SDAP and PDCP (ciphered with the core's keys), KAIR, the DU, F1-U/NR-U, and the CU-UP's PDCP and SDAP.

**Later (scale mode):** an eBPF express path modelled on PacketRusher bypasses PDCP for throughput and load tests. The control plane stays at full fidelity either way.

Research: [`research/packetrusher.md`](research/packetrusher.md), [`research/ueransim-fork.md`](research/ueransim-fork.md).

## 1. Per-UE network namespace

Each UE gets a netns `ksim-ue-<n>`. It is created by `ksim-netd`, the privileged helper of [ADR 0009](adr/0009-p1-runtime-shape.md) (unprivileged user namespaces are restricted by AppArmor), and bind-mounted into `/run/netns`, so `ip netns exec` and `ksim-ctl ue <n> exec …` work.

- **One TUN per PDU session,** `pdu<psi>` (IFF_TUN | IFF_NO_PI), created inside the netns. The farm keeps one rtnetlink socket per netns.
- **IPv6 sysctls are set before the interface exists.**
  - IPv4-only session: `disable_ipv6` in `default` and `all`.
  - IPv6 session: `addr_gen_mode=1`, `ip token ::<IID from the PDU address>` and `accept_ra=1`, with a per-persona noise profile (`quiet` or `phone`).

  This removes the race behind kaluza-core's P-33, where the host kernel sent RS and MLD into UERANSIM's tunnels and woke idle UEs. It isn't patched after an address appears; the race never happens.
- **Routing:** one table per session plus `ip rule from <addr>`; the default route goes to the persona's preferred DNN. URSP-driven routing comes later.
- **DNS** from ePCO, written to `/etc/netns/<ns>/resolv.conf`. **MTU** from the ePCO IPv4 link MTU, as phones request it. That avoids the F-28 class, where packets over 1456 octets were lost in N3's 44-octet tunnel overhead.
- **Host-noise visibility:** a counter and event for RS, MLD and ND, so a gate can name why a UE left CM-IDLE.
- **Applications** run inside the UE: `ksim-ctl ue <n> exec ping|iperf3|curl …` ([`cli.md`](cli.md)).

**As built in P1 N11** (rows KS-PLAT-B25, B26; not yet run on a real kernel, row KS-PLAT-G7):
- `ksim-netd` does the system's part: `setup_ue` (IPv6 off in `all` and `default` and `ping_group_range` open, written before any link is up, then lo), `tun` (the device opened inside the namespace, MTU, address /32, up, a default route in table 100 + PSI and `ip rule from <addr>`, the first session also the main default route), `tun_down`, `resolv`, and `exec` as the asking user. ksim takes the TUN's descriptor and reads it on its reactor; it never joins a namespace. The farm uses netd's requests instead of a socket per namespace.
- The default route and the resolv.conf go to the first session, not yet the persona's preferred DNN (personas are N15).
- IPv6 sessions are v1.x, so P1's namespaces have IPv6 off in all cases. The noise counter counts any uplink packet that is not IPv4 from the session's address; with IPv6 off before link-up it stays 0.
- A run without netd has no namespaces: its UEs run in inject mode (N10), where ksim builds the echo requests itself; `exec` is refused there.
- The topology says what netd makes: `netd: {nodes: true|false, ues: true|false}` (the privileged CI hook runs the UEs in namespaces and the nodes on loopback beside the stub).

## 2. The v1 path (user space, fidelity)

**Uplink:**
1. TUN read, in batches of up to 64.
2. QoS-rule classifier (TS 24.501 §6.2.5, §9.11.4.13): rules in precedence order, plus reflective (derived) rules.
3. SDAP: QFI header and QFI → DRB mapping (TS 37.324).
4. PDCP: NEA/NIA, COUNT (TS 38.323).
5. IdealRlc, then KAIR `UL_SDU`, to the DU.
6. The DU sends it over F1-U (NR-U).
7. The CU-UP's PDCP: receive window, t-Reordering.
8. The CU-UP's SDAP checks the QFI.
9. GTP-U on N3, with the UL PDU Session Container (type 1, QFI) per TS 38.415.

**Downlink:**
1. QFI and RQI come from the type-0 PDU Session Container.
2. SDAP sets RDI/RQI.
3. PDCP.
4. NR-U DL USER DATA to the DU.
5. KAIR `DL_SDU` to the UE.
6. The UE's PDCP.
7. The UE's SDAP derives reflective rules and runs the RQ timer.
8. TUN write.

**I/O:**
- `recvmmsg` and `sendmmsg`.
- A pooled, contiguous `PacketBuf` with 128 bytes of headroom, so headers are prepended without copying.
- One farm shard should sustain about 1 Gbit/s with AES-NI. Targets: [`requirements.md`](requirements.md) §3.5.

**Diagnostics:**
- `ksim_pdcp_decipher_sanity_fail_total` counts deciphered DRB SDUs that don't parse as IP. On bearers without integrity protection, this pinpoints a key or COUNT desynchronisation.
- Unknown-QFI drops are counted and raise an event (KS-SDAP-002). The UE never silently ignores the DL QFI, as UERANSIM did.

## 3. CU-UP (`ksim-cuup`)

- **GTP-U endpoints** per local IP for NG-U, F1-U and Xn-U. TEIDs carry shard bits.
  - Echo request/response.
  - **Error Indication** sent for an unknown TEID, and acted on when received.
  - Supported Extension Headers Notification.
  - End Marker (TS 29.281 §5, §7.2, §7.3).
- **NR-U:** DL USER DATA and DL DATA DELIVERY STATUS (highest delivered PDCP SN, desired buffer size) per TS 38.425.
- **Handover:**
  - `HoBuffer` delivers forwarded SDUs first, then new-path SDUs after the End Marker or a timeout.
  - Forwarding over Xn-U (Xn handover) or through the UPF's indirect tunnels (N2 handover).
  - The PDCP SN is preserved for AM DRBs.
- **Fragmentation:** reassembly of fragmented GTP-U packets at realistic MTUs, with no jumbo frames (TS 38.414 §5.3).

## 4. Seams for scale (later)

`IUeDataPath` is chosen per session:
- **`Fidelity`:** §2 above.
- **`Express`:** below. The CU-UP hands its tunnel state to the express path with `bindExpress()`; the control plane stays untouched.

### 4.1 What PacketRusher does (local clone `/home/amadeus/Development/ref/PacketRusher`, HEAD 7836091, Apache-2.0)

`--tunnel-backend auto|ebpf|gtp5g|userspace`. The eBPF backend is `internal/control_test_engine/ue/gtp/ebpfgtp/bpf/gtpu.c` (PR #223, 2026-10-05). It keeps a TUN per UE and attaches three TCX programs, which need Linux 6.6 or later:
1. **`uplink`** on the TUN's egress: looks up `uplinks[ifindex]`, checks the source address (the UE's IPv4 address or IPv6 /64), adds an Ethernet header, marks the skb and redirects to a veth "stage".
2. **The stage veth** has MTU 65535 and TX checksum offload off, so the kernel segments GSO and fills in checksums.
3. **`encap`** on the stage's ingress: builds outer IPv4, UDP 2152 and GTP-U, with a 0x85 PDU Session Container carrying the QFI. It computes the IPv4 checksum (the UDP checksum is 0) and calls `bpf_redirect_neigh(n3)`.
4. **`decap`** on N3's ingress: looks up `downlinks[{local N3 addr, TEID}]`, strips the outer headers and calls `bpf_redirect(tun, BPF_F_INGRESS)`. The kernel then delivers the packet to sockets bound to the UE's IP.

Anything the programs don't handle (Echo, IPv6 RA, fragments, multi-segment GSO, unknown TEIDs) returns `TC_ACT_UNSPEC` and falls back to user space.

The README reports about 3.4/4.7 Gbit/s UL/DL for one UE and 10/14 Gbit/s for four UEs (iperf3 TCP against free5GC's UPF).

**Its limits:**
- one QFI per session;
- only PDU session 1 is tunnelled;
- everything sits in the host namespace (a dummy device and a policy table or VRF per UE);
- no RRC or radio layers.

### 4.2 kaluza-sim's express path (design; built in the scale phase)

- **veth `pdu<psi>` inside the UE netns** instead of a TUN, with its peer in the root netns. Per-UE isolation is kept.
- **TCX ingress on the peer:**
  - takes the QFI from an **eBPF copy of the UE's QoS rules** (precedence-ordered packet filters, bounded loops), which removes PacketRusher's one-QFI limit;
  - encapsulates GTP-U with the 0x85 container;
  - calls `bpf_redirect_neigh` to N3.
- **TCX ingress on N3:** decapsulates by {local address, TEID} and calls **`bpf_redirect_peer`** into the UE netns.
- **Reflective QoS:** an RQI seen in decap raises an event, so the UE's NAS layer updates the derived rules in the map.
- **Fallback to user space** for Echo, Error Indication, End Marker, RA/RS, fragments and unknown TEIDs.
- **Licensing:** PacketRusher code copied into `third_party/packetrusher/` keeps its Apache-2.0 header and gets a NOTICE entry ([ADR 0004](adr/0004-clean-room-licensing.md)).
- **Higher CU-UP throughput:** AF_XDP for the CU-UP sockets, UDP_SEGMENT/GRO, and SO_REUSEPORT with a TEID-shard eBPF selector.

## 5. Comparison

| | UERANSIM fork | PacketRusher (ebpf) | kaluza-sim v1 (Fidelity) | kaluza-sim later (Express) |
|---|---|---|---|---|
| UE ↔ gNB | RLS over UDP: RRC and raw IP, no PDCP | In-process Go channels, no RRC | KAIR: real RRC, PDCP and SDAP over an ideal RLC/MAC | Control plane as v1; user plane bypasses PDCP |
| Isolation | TUN per session in the host netns, policy routing | Host netns, a policy table or VRF per UE | **A netns per UE**, a TUN per session | A netns per UE, a veth per session |
| QoS | UL classifier; DL QFI ignored | One QFI per session | Full QoS rules, reflective QoS, unknown QFI counted | Multiple QFIs via eBPF rule maps |
| Throughput | About 350/470 Mbit/s per UE after its fast path | About 3.4/4.7 Gbit/s per UE | ≥ 200/100 Mbit/s per UE with NEA2 (target) | Multi-Gbit/s (target) |
| Scale | 512 UEs per process, 6–8 threads per UE | 10k UEs claimed | About 100 UEs (v1) | 10k+ |
