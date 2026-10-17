// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// OCUDU as an independent reader of our RRC (P3 R0 spike 2, R1's offline oracle;
// ADR 0013 point 13): each stdin line "<type>\t<hex>" is unpacked by OCUDU's own
// ASN.1 decoder and packed again, one line out per PDU:
//
//   <type>\tUNPACK=OK|FAIL\tREPACK=SAME|DIFF|-\t<the fields OCUDU's CU-CP reads>
//
// OCUDU's CU-CP calls report_fatal_error when a target DU's CellGroupConfig or
// its dedicated SIB1 fails to unpack (lib/cu_cp/routines/mobility/
// handover_reconfiguration_routine.cpp) and reads t304, t301 and t311 from
// them, so those are printed. Built against the pinned OCUDU tree's static
// libraries (tools/ocudu_vectors/unpack.sh); nothing of OCUDU is copied here.

#include "ocudu/asn1/asn1_utils.h"
#include "ocudu/asn1/rrc_nr/cell_group_config.h"
#include "ocudu/asn1/rrc_nr/dl_dcch_msg.h"
#include "ocudu/asn1/rrc_nr/dl_dcch_msg_ies.h"
#include "ocudu/asn1/rrc_nr/rrc_nr.h"
#include "ocudu/asn1/rrc_nr/sys_info.h"

#include <cstdio>
#include <iostream>
#include <string>

using namespace ocudu;

namespace {

byte_buffer from_hex(const std::string& h) {
  byte_buffer b;
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
    (void)b.append(static_cast<uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
  }
  return b;
}

std::string to_hex(const byte_buffer& b) {
  static const char* d = "0123456789abcdef";
  std::string out;
  for (uint8_t c : b) {
    out += d[c >> 4];
    out += d[c & 0xf];
  }
  return out;
}

template <class T>
bool repack_same(const T& v, const std::string& hex) {
  byte_buffer   b;
  asn1::bit_ref bref(b);
  return v.pack(bref) == asn1::OCUDUASN_SUCCESS && to_hex(b) == hex;
}

void cell_group(const std::string& hex) {
  asn1::rrc_nr::cell_group_cfg_s c;
  byte_buffer                    in = from_hex(hex);
  asn1::cbit_ref                 bref(in);
  if (c.unpack(bref) != asn1::OCUDUASN_SUCCESS) {
    std::printf("CellGroupConfig\tUNPACK=FAIL\tREPACK=-\t-\n");
    return;
  }
  const auto& s = c.sp_cell_cfg;
  const auto& r = s.recfg_with_sync;
  std::printf("CellGroupConfig\tUNPACK=OK\tREPACK=%s\tsp_cell=%d recfg_with_sync=%d t304_ms=%u new_ue_id=%u "
              "common=%d pci=%u ssb_arfcn=%u rach_ded=%d cfra=%d\n",
              repack_same(c, hex) ? "SAME" : "DIFF",
              int(c.sp_cell_cfg_present),
              int(s.recfg_with_sync_present),
              unsigned(r.t304.to_number()),
              unsigned(r.new_ue_id),
              int(r.sp_cell_cfg_common_present),
              unsigned(r.sp_cell_cfg_common.pci_present ? r.sp_cell_cfg_common.pci : 9999),
              unsigned(r.sp_cell_cfg_common.dl_cfg_common_present &&
                               r.sp_cell_cfg_common.dl_cfg_common.freq_info_dl_present &&
                               r.sp_cell_cfg_common.dl_cfg_common.freq_info_dl.absolute_freq_ssb_present
                           ? r.sp_cell_cfg_common.dl_cfg_common.freq_info_dl.absolute_freq_ssb
                           : 0),
              int(r.rach_cfg_ded_present),
              int(r.rach_cfg_ded_present && r.rach_cfg_ded.type().value == asn1::rrc_nr::recfg_with_sync_s::rach_cfg_ded_c_::types::ul &&
                  r.rach_cfg_ded.ul().cfra_present));
}

std::string hex_of(const asn1::dyn_octstring& o) {
  static const char* d = "0123456789abcdef";
  std::string out;
  for (uint8_t c : o) {
    out += d[c >> 4];
    out += d[c & 0xf];
  }
  return out;
}

/// An RRCReconfiguration's fields OCUDU's CU-CP and UE paths read; its masterCellGroup
/// goes through cell_group() as well, on its own line.
bool recfg(const char* type, const asn1::rrc_nr::rrc_recfg_s& r, const std::string& hex, bool repack) {
  if (r.crit_exts.type().value != asn1::rrc_nr::rrc_recfg_s::crit_exts_c_::types::rrc_recfg) {
    std::printf("%s\tUNPACK=OK\tREPACK=%s\tcrit_exts=future\n", type, repack ? "SAME" : "DIFF");
    return true;
  }
  const auto& ies = r.crit_exts.rrc_recfg();
  const bool v1530 = ies.non_crit_ext_present;
  const auto& ext  = ies.non_crit_ext;
  std::printf("%s\tUNPACK=OK\tREPACK=%s\tradio_bearers=%d master_cell_group=%d master_key_upd=%d ncc=%u "
              "key_set_change=%d\n",
              type, repack ? "SAME" : "DIFF", int(ies.radio_bearer_cfg_present),
              int(v1530 && !ext.master_cell_group.empty()), int(v1530 && ext.master_key_upd_present),
              unsigned(v1530 && ext.master_key_upd_present ? ext.master_key_upd.next_hop_chaining_count : 0),
              int(v1530 && ext.master_key_upd_present && ext.master_key_upd.key_set_change_ind));
  if (v1530 && !ext.master_cell_group.empty()) {
    cell_group(hex_of(ext.master_cell_group));
  }
  (void)hex;
  return true;
}

void dl_dcch(const std::string& hex) {
  asn1::rrc_nr::dl_dcch_msg_s m;
  byte_buffer                 in = from_hex(hex);
  asn1::cbit_ref              bref(in);
  if (m.unpack(bref) != asn1::OCUDUASN_SUCCESS || m.msg.type().value != asn1::rrc_nr::dl_dcch_msg_type_c::types::c1) {
    std::printf("RRCReconfiguration\tUNPACK=FAIL\tREPACK=-\t-\n");
    return;
  }
  if (m.msg.c1().type().value != asn1::rrc_nr::dl_dcch_msg_type_c::c1_c_::types::rrc_recfg) {
    std::printf("DL-DCCH\tUNPACK=OK\tREPACK=%s\tnot an RRCReconfiguration\n", repack_same(m, hex) ? "SAME" : "DIFF");
    return;
  }
  recfg("RRCReconfiguration", m.msg.c1().rrc_recfg(), hex, repack_same(m, hex));
}

void ho_prep(const std::string& hex) {
  asn1::rrc_nr::ho_prep_info_s h;
  byte_buffer                  in = from_hex(hex);
  asn1::cbit_ref               bref(in);
  if (h.unpack(bref) != asn1::OCUDUASN_SUCCESS ||
      h.crit_exts.type().value != asn1::rrc_nr::ho_prep_info_s::crit_exts_c_::types::c1) {
    std::printf("HandoverPreparationInformation\tUNPACK=FAIL\tREPACK=-\t-\n");
    return;
  }
  const auto& ies = h.crit_exts.c1().ho_prep_info();
  std::printf("HandoverPreparationInformation\tUNPACK=OK\tREPACK=%s\tue_caps=%u source_cfg=%d as_context=%d\n",
              repack_same(h, hex) ? "SAME" : "DIFF", unsigned(ies.ue_cap_rat_list.size()), int(ies.source_cfg_present),
              int(ies.as_context_present));
  if (ies.source_cfg_present) {
    asn1::rrc_nr::rrc_recfg_s r;
    asn1::cbit_ref            b2(ies.source_cfg.rrc_recfg);
    if (r.unpack(b2) != asn1::OCUDUASN_SUCCESS) {
      std::printf("AS-Config.rrcReconfiguration\tUNPACK=FAIL\tREPACK=-\t-\n");
    } else {
      recfg("AS-Config.rrcReconfiguration", r, hex_of(ies.source_cfg.rrc_recfg), true);
    }
  }
}

void ho_cmd(const std::string& hex) {
  asn1::rrc_nr::ho_cmd_s h;
  byte_buffer            in = from_hex(hex);
  asn1::cbit_ref         bref(in);
  if (h.unpack(bref) != asn1::OCUDUASN_SUCCESS ||
      h.crit_exts.type().value != asn1::rrc_nr::ho_cmd_s::crit_exts_c_::types::c1) {
    std::printf("HandoverCommand\tUNPACK=FAIL\tREPACK=-\t-\n");
    return;
  }
  const auto& msg = h.crit_exts.c1().ho_cmd().ho_cmd_msg;
  std::printf("HandoverCommand\tUNPACK=OK\tREPACK=%s\tmessage_octets=%u\n", repack_same(h, hex) ? "SAME" : "DIFF",
              unsigned(msg.size()));
  asn1::rrc_nr::rrc_recfg_s r;
  asn1::cbit_ref            b2(msg);
  if (r.unpack(b2) != asn1::OCUDUASN_SUCCESS) {
    std::printf("HandoverCommand.rrcReconfiguration\tUNPACK=FAIL\tREPACK=-\t-\n");
  } else {
    recfg("HandoverCommand.rrcReconfiguration", r, hex_of(msg), true);
  }
}

void sib1(const std::string& hex) {
  asn1::rrc_nr::sib1_s s;
  byte_buffer          in = from_hex(hex);
  asn1::cbit_ref       bref(in);
  if (s.unpack(bref) != asn1::OCUDUASN_SUCCESS) {
    std::printf("SIB1\tUNPACK=FAIL\tREPACK=-\t-\n");
    return;
  }
  std::printf("SIB1\tUNPACK=OK\tREPACK=%s\tt301_ms=%u t311_ms=%u\n", repack_same(s, hex) ? "SAME" : "DIFF",
              unsigned(s.ue_timers_and_consts.t301.to_number()), unsigned(s.ue_timers_and_consts.t311.to_number()));
}

} // namespace

int main() {
  std::string line;
  while (std::getline(std::cin, line)) {
    const auto tab = line.find('\t');
    if (line.empty() || line[0] == '#' || tab == std::string::npos) {
      continue;
    }
    const std::string type = line.substr(0, tab);
    const std::string hex  = line.substr(tab + 1);
    if (type == "CellGroupConfig") {
      cell_group(hex);
    } else if (type == "SIB1") {
      sib1(hex);
    } else if (type == "RRCReconfiguration" || type == "DL-DCCH") {
      dl_dcch(hex);
    } else if (type == "HandoverPreparationInformation") {
      ho_prep(hex);
    } else if (type == "HandoverCommand") {
      ho_cmd(hex);
    } else {
      std::printf("%s\tUNPACK=UNKNOWN\tREPACK=-\t-\n", type.c_str());
    }
  }
  return 0;
}
