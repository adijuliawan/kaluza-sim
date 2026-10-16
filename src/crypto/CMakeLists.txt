# SPDX-FileCopyrightText: 2026 Adi Juliawan
# SPDX-License-Identifier: LicenseRef-kaluza-sim-private
#
# crypto: pure functions over OpenSSL and the vendored SNOW 3G kernel (rule R2):
# no I/O, no time, no threads. Keys stay in SecretBytes.

add_library(ksim_crypto STATIC
    aes.cpp
    kdf.cpp
    milenage.cpp
    keys5g.cpp
    as_security.cpp
    nea.cpp
    keccak.cpp
    tuak.cpp
    rijndael256.cpp
    milenage256.cpp
    ecies.cpp
    eap_aka_prime.cpp
    aead.cpp)
add_library(ksim::crypto ALIAS ksim_crypto)
target_include_directories(ksim_crypto PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(ksim_crypto
    PUBLIC ksim::platform OpenSSL::Crypto
    PRIVATE ksim_ocudu_security ksim::warnings)
ksim_layer(ksim_crypto crypto)
