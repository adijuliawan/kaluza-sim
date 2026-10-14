/* SPDX-FileCopyrightText: 2026 Adi Juliawan
 * SPDX-License-Identifier: LicenseRef-kaluza-sim-private
 *
 * The one ASN.1 runtime configuration (architecture.md §4.1, row KS-PLAT-B4).
 * Force-included (-include) into every translation unit that touches asn1c
 * code: the vendored runtime, every generated protocol library and our C++
 * wrappers. asn_encoding_constraints_t and the type descriptors change layout
 * with these macros, so a translation unit that saw a different set would
 * silently disagree with the rest.
 *
 * Generated with: -no-gen-OER -no-gen-BER -no-gen-XER -no-gen-random-fill.
 * Kept: UPER (RRC), APER (NGAP, F1AP, E1AP, XnAP), JER (oracle comparison and
 * the ksim-codec dump), print.
 */
#ifndef KSIM_ASN1_CONFIG_H
#define KSIM_ASN1_CONFIG_H

#define ASN_DISABLE_OER_SUPPORT 1
#define ASN_DISABLE_BER_SUPPORT 1
#define ASN_DISABLE_XER_SUPPORT 1
#define ASN_DISABLE_RFILL_SUPPORT 1

#endif /* KSIM_ASN1_CONFIG_H */
