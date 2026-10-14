# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""kaluza-sim's oracle harness (plan M8, verification.md §2).

Independent of the C++ codecs it judges:
  pcap      writes the capture formats tshark reads (Exported-PDU, raw IPv4/UDP, GSMTAP)
  tshark    runs tshark on stdin (AppArmor blocks paths under ~/Development) and
            returns per-packet leaves, malformed flags and expert errors
  asn       pycrate compiled from OUR extracted Rel-19 ASN.1, cached by stamp
  compare   JER normalisation and the leaf-coverage check against tshark
  valuegen  minimal, maximal and boundary values per PDU type, from pycrate's types

Wireshark and pycrate are GPL/LGPL: they run as external processes or in
the oracle venv, never linked into kaluza-sim (ADR 0004).
"""
