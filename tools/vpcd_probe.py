#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
"""Probes the card bridge (P2 Q1; lab.md section 7, row ksim-p2.bridge-refuses-admin).

Connects to `ksim-sim serve --pcsc` as a terminal does, over the vpcd framing
(a 2-octet big-endian length, then the payload; a 1-octet payload is a
control code), and sends what only an administrator may:

  VERIFY ADM1 with no data       (the retry-counter query: harmless even if it
                                  reached the card, so a broken filter cannot
                                  cost the card a try)
  UPDATE BINARY of AF20, 1 octet (ADM1 is never verified on this connection,
                                  so the card refuses it in any case)

and, as a control, VERIFY PIN1 with no data, which must pass. Prints
VERIFY_ADM1_SW=, UPDATE_AF20_SW= and VERIFY_PIN1_STATUS_SW= (hex). The bridge
refuses the first two itself with 6982.

    tools/vpcd_probe.py --connect 127.0.0.1:35970
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys


def send(s: socket.socket, payload: bytes) -> None:
    s.sendall(struct.pack(">H", len(payload)) + payload)


def recv(s: socket.socket) -> bytes:
    def exact(n: int) -> bytes:
        b = b""
        while len(b) < n:
            chunk = s.recv(n - len(b))
            if not chunk:
                raise ConnectionError("the bridge closed the connection")
            b += chunk
        return b
    (n,) = struct.unpack(">H", exact(2))
    return exact(n)


def apdu(s: socket.socket, c: bytes) -> bytes:
    send(s, c)
    r = recv(s)
    while len(r) >= 2 and r[-2] == 0x61:   # T=0: GET RESPONSE for the rest
        send(s, bytes([0x00, 0xC0, 0x00, 0x00, r[-1]]))
        r = recv(s)
    return r


def sw(r: bytes) -> str:
    return r[-2:].hex().upper() if len(r) >= 2 else "none"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--connect", required=True, help="the bridge, host:port")
    ap.add_argument("--timeout", type=float, default=5.0)
    a = ap.parse_args()
    host, _, port = a.connect.rpartition(":")
    with socket.create_connection((host, int(port)), timeout=a.timeout) as s:
        send(s, b"\x01")                      # power on
        send(s, b"\x04")                      # the ATR, please
        atr = recv(s)
        print(f"ATR={atr.hex().upper()}")
        apdu(s, bytes.fromhex("00A40004023F00"))
        apdu(s, bytes.fromhex("00A4040407A0000000871002"))
        print(f"VERIFY_PIN1_STATUS_SW={sw(apdu(s, bytes.fromhex('00200001')))}")
        print(f"VERIFY_ADM1_SW={sw(apdu(s, bytes.fromhex('0020000A')))}")
        apdu(s, bytes.fromhex("00A4000402AF20"))
        print(f"UPDATE_AF20_SW={sw(apdu(s, bytes.fromhex('00D600000100')))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
