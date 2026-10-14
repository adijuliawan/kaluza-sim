// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// OCUDU as an independent producer (plan M10, ADR 0005): OCUDU's own test
// message builders, packed by OCUDU's own ASN.1 encoder, printed one PDU per
// line as "<protocol>\t<builder>\t<hex>". Built against a local OCUDU tree and
// its prebuilt libraries (read-only) by tools/ocudu_vectors/build.sh; nothing of
// OCUDU is copied into kaluza-sim. The values are OCUDU's synthetic test values
// (test PLMN 001/01), so the output is committed as a corpus source.

#include "tests/test_doubles/f1ap/f1ap_test_messages.h"
#include "tests/test_doubles/rrc/rrc_packed_test_messages.h"
#include "tests/test_doubles/utils/test_rng_seed.h"
#include "tests/unittests/e1ap/common/e1ap_cu_cp_test_messages.h"
#include "tests/unittests/e1ap/common/e1ap_cu_up_test_messages.h"
#include "tests/unittests/ngap/ngap_test_messages.h"
#include "tests/unittests/xnap/xnap_test_messages.h"
#include "ocudu/asn1/asn1_utils.h"
#include "ocudu/e1ap/common/e1ap_message.h"
#include "ocudu/f1ap/f1ap_message.h"
#include "ocudu/ngap/ngap_message.h"
#include "ocudu/xnap/xnap_message.h"

#include <cstdio>
#include <string>

using namespace ocudu;

namespace {

std::string hex(const byte_buffer& b) {
  static const char* d = "0123456789abcdef";
  std::string out;
  for (uint8_t c : b) {
    out += d[c >> 4];
    out += d[c & 0xf];
  }
  return out;
}

template <class Msg>
void emit(const char* proto, const char* name, const Msg& m) {
  byte_buffer   b;
  asn1::bit_ref bref(b);
  if (m.pdu.pack(bref) != asn1::OCUDUASN_SUCCESS) {
    std::fprintf(stderr, "PACK_FAIL %s %s\n", proto, name);
    return;
  }
  std::printf("%s\t%s\t%s\n", proto, name, hex(b).c_str());
}

void emit_bytes(const char* proto, const char* name, const byte_buffer& b) {
  std::printf("%s\t%s\t%s\n", proto, name, hex(b).c_str());
}

#define F1(name, ...) emit("f1ap", #name, test_helpers::name(__VA_ARGS__))
#define E1CP(name, ...) emit("e1ap", #name, ocucp::name(__VA_ARGS__))
#define E1UP(name, ...) emit("e1ap", #name, ocuup::name(__VA_ARGS__))
#define NG(name, ...) emit("ngap", #name, ocucp::name(__VA_ARGS__))
#define XN(name, ...) emit("xnap", #name, ocucp::name(__VA_ARGS__))

} // namespace

int main() {
  test_rng::init_base_seed(1);  // OCUDU's builders draw some values at random: a fixed seed keeps the output stable
  const auto cu = int_to_gnb_cu_ue_f1ap_id(7);
  const auto du = int_to_gnb_du_ue_f1ap_id(9);
  const nr_cell_global_id_t cgi{plmn_identity::test_value(), nr_cell_identity::create(0x66c000).value()};

  // F1AP
  const f1ap_message f1_setup = test_helpers::generate_f1_setup_request();
  emit("f1ap", "generate_f1_setup_request", f1_setup);
  F1(generate_f1_setup_response, f1_setup);
  F1(generate_f1_setup_failure, f1_setup);
  F1(generate_f1ap_reset_message);
  F1(generate_gnb_cu_configuration_update_request, 1, span<const nr_cell_global_id_t>(&cgi, 1));
  F1(generate_gnb_cu_configuration_update_acknowledgement, {});
  F1(generate_gnb_cu_configuration_update_failure);
  F1(generate_f1_removal_request, 2);
  F1(generate_ue_context_setup_request, cu, du, 1, {drb_id_t::drb1}, cgi);
  F1(generate_ue_context_setup_response, cu, du);
  F1(generate_ue_context_setup_failure, cu, du);
  F1(generate_ue_context_release_request, cu, du);
  const f1ap_message rel_cmd = test_helpers::generate_ue_context_release_command(cu, du);
  emit("f1ap", "generate_ue_context_release_command", rel_cmd);
  F1(generate_ue_context_release_complete, rel_cmd);
  F1(generate_ue_context_modification_request, du, cu, {drb_id_t::drb1});
  F1(generate_ue_context_modification_response, du, cu);
  F1(generate_ue_context_modification_failure, cu, du);
  F1(generate_init_ul_rrc_message_transfer, du);
  F1(generate_dl_rrc_message_transfer, du, cu, srb_id_t::srb1, test_helpers::create_dl_dcch_rrc_container(0, {0x2a, 0x00}));
  F1(generate_ul_rrc_message_transfer, du, cu);
  F1(generate_f1ap_paging_message, 0x123456789aULL);

  // E1AP
  const auto cp = int_to_gnb_cu_cp_ue_e1ap_id(3);
  const auto up = int_to_gnb_cu_up_ue_e1ap_id(5);
  E1CP(generate_valid_cu_up_e1_setup_request);
  E1UP(generate_cu_up_e1_setup_response, 1);
  E1CP(generate_valid_e1_release_request);
  E1UP(generate_bearer_context_setup_request, 3);
  E1CP(generate_bearer_context_setup_failure, cp, up);
  E1UP(generate_bearer_context_modification_request, 3, 5);
  E1CP(generate_bearer_context_modification_failure, cp, up);
  E1UP(generate_bearer_context_release_command, 3, 5);
  E1CP(generate_bearer_context_release_complete, cp, up);
  E1CP(generate_bearer_context_release_request, cp, up);
  E1CP(generate_bearer_context_inactivity_notification_with_ue_level, cp, up);
  E1CP(generate_dl_data_notification_message, cp, up);
  E1UP(generate_e1_reset, {{cp, up}});

  // NGAP
  const auto amf = ocucp::uint_to_amf_ue_id(11);
  const auto ran = uint_to_ran_ue_id(13);
  NG(generate_ng_setup_response);
  NG(generate_ng_setup_failure);
  NG(generate_uplink_nas_transport_message, amf, ran);
  NG(generate_valid_initial_context_setup_request_message, amf, ran);
  NG(generate_valid_initial_context_setup_request_message_with_pdu_session, amf, ran);
  NG(generate_valid_ue_context_modification_request_message, amf, ran);
  NG(generate_valid_ue_context_release_command_with_ue_ngap_id_pair, amf, ran);
  NG(generate_valid_pdu_session_resource_release_command, amf, ran, uint_to_pdu_session_id(1));
  NG(generate_pdu_session_resource_modify_request_base, amf, ran);
  NG(generate_valid_minimal_paging_message);
  NG(generate_valid_paging_message);
  NG(generate_error_indication_message, amf, ran);
  NG(generate_valid_handover_request, amf);
  NG(generate_handover_preparation_failure, amf, ran);
  NG(generate_valid_handover_command, amf, ran);
  NG(generate_valid_dl_ran_status_transfer, amf, ran);
  NG(generate_handover_cancel_ack, amf, ran);
  NG(generate_location_reporting_control_message, amf, ran);
  NG(generate_path_switch_request_ack, amf, ran);

  // XnAP
  const auto lx = ocucp::uint_to_local_xnap_ue_id(1);
  const auto px = ocucp::uint_to_peer_xnap_ue_id(2);
  XN(generate_handover_request, lx);
  XN(generate_handover_preparation_failure, px);
  XN(generate_handover_request_ack, lx, px);
  XN(generate_sn_status_transfer, lx, px);
  XN(generate_ue_context_release, lx, px);

  // RRC containers
  emit_bytes("rrc", "create_meas_timing_cfg", test_helpers::create_meas_timing_cfg(632628, subcarrier_spacing::kHz30));
  emit_bytes("rrc", "create_cell_group_config", test_helpers::create_cell_group_config());
  return 0;
}
