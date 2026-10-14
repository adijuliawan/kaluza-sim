/* SPDX-FileCopyrightText: 2026 Adi Juliawan
 * SPDX-License-Identifier: LicenseRef-kaluza-sim-private
 *
 * APER round trip of the smoke module: build a message, encode, decode,
 * re-encode, and require identical bytes and the 4e12 BitRate back.
 * The prefix (SA_) comes from run.sh.
 */
#include <stdio.h>
#include <string.h>

#include "SA_Msg.h"
#include "SA_ProtocolIE-Field.h"

static int to_stdout(const void* b, size_t s, void* k) {
    return fwrite(b, 1, s, (FILE*)k) == s ? 0 : -1;
}

int main(void) {
    SA_Msg_t* m = calloc(1, sizeof *m);
    SA_MsgIEs_t* ie1 = calloc(1, sizeof *ie1);
    ie1->id = 1;
    ie1->criticality = SA_Criticality_reject;
    ie1->value.present = SA_MsgIEs__value_PR_Cause;
    ie1->value.choice.Cause.present = SA_Cause_PR_transport;
    ie1->value.choice.Cause.choice.transport = 3;
    ASN_SEQUENCE_ADD(&m->protocolIEs.list, ie1);
    SA_MsgIEs_t* ie2 = calloc(1, sizeof *ie2);
    ie2->id = 2;
    ie2->criticality = SA_Criticality_ignore;
    ie2->value.present = SA_MsgIEs__value_PR_BitRate;
    asn_long2INTEGER(&ie2->value.choice.BitRate, 4000000000000L);
    ASN_SEQUENCE_ADD(&m->protocolIEs.list, ie2);

    uint8_t buf[256], buf2[256];
    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_SA_Msg, NULL, m, buf, sizeof buf);
    if (er.encoded < 0) {
        printf("SMOKE_ENCODE=FAIL\n");
        return 1;
    }
    size_t n = (size_t)(er.encoded + 7) / 8;
    SA_Msg_t* d = NULL;
    asn_dec_rval_t dr = aper_decode_complete(NULL, &asn_DEF_SA_Msg, (void**)&d, buf, n);
    if (dr.code != RC_OK) {
        printf("SMOKE_DECODE=FAIL\n");
        return 1;
    }
    asn_enc_rval_t er2 = aper_encode_to_buffer(&asn_DEF_SA_Msg, NULL, d, buf2, sizeof buf2);
    long v = 0;
    asn_INTEGER2long(&d->protocolIEs.list.array[1]->value.choice.BitRate, &v);
    int same = er2.encoded == er.encoded && memcmp(buf, buf2, n) == 0;
    printf("SMOKE_APER_BYTES=%zu\nSMOKE_ROUNDTRIP=%s\nSMOKE_BITRATE=%ld\n", n,
           same ? "IDENTICAL" : "DIFFERENT", v);
    if (jer_encode(&asn_DEF_SA_Msg, d, JER_F, to_stdout, stdout).encoded < 0) {
        printf("SMOKE_JER=FAIL\n");
        return 1;
    }
    ASN_STRUCT_FREE(asn_DEF_SA_Msg, m);
    ASN_STRUCT_FREE(asn_DEF_SA_Msg, d);
    return same && v == 4000000000000L ? 0 : 1;
}
