// SPDX-FileCopyrightText: 2026 Adi Juliawan
// SPDX-License-Identifier: LicenseRef-kaluza-sim-private
//
// kaluza-core's UDR provisioning API from the dev PC (P1 N9; ADR 0008,
// sim-uicc.md 8): a client_credentials token from Keycloak for the client
// kaluza-sim-key-entry, then one PUT (or DELETE) per subscriber on the UDR's
// provisioning listener, over mTLS with the client certificate. The
// credentials are read from their 0600 files at run time and never printed;
// bodies and the token stay in memory and are wiped after use. HTTPS is
// cpp-httplib with OpenSSL in-process, so no key or token is in an argv.

#pragma once

#include <map>
#include <string>

namespace ksim::sim {

struct KaluzaApi {
    std::string token_url;                      // https://host[:port]/path
    std::string udr_url;                        // https://host:port (before /provisioning/v1/…)
    std::map<std::string, std::string> resolve; // host name -> address, as curl --resolve
    std::string cred_dir;                       // the client secret, tls-chain.pem, tls.key, root.pem
    std::string secret_file = "client-secret";  // the client secret's file name in cred_dir
    std::string client_id = "kaluza-sim-key-entry";
    bool token_mtls = false;                    // the client certificate on the token request too
};

/// Each IMSI's bundle with K and OPc from the master; prints UE_ID, STATUS
/// and K_FPR only. With dry_run, nothing is sent and each bundle is printed
/// with its keys replaced by placeholders, for the core session to check.
/// A new subscriber is a PUT with If-None-Match: * (201, or 412 when it
/// exists); with replace, an existing one is read first and replaced with
/// If-Match: <its ETag> (a missing one is created as above).
int kaluza_provision(const std::string& first, unsigned count, const std::string& master_file, const KaluzaApi& api,
                     bool dry_run, bool replace);
int kaluza_deprovision(const std::string& first, unsigned count, const KaluzaApi& api);

} // namespace ksim::sim
