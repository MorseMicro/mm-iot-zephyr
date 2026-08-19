# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(LIB_NAME mmmbedtls)
set(SRC
    ${MMIOT_ROOT}/framework/src/mbedtls/library/aes.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/aria.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/asn1parse.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/asn1write.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/base64.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/bignum.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/bignum_core.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/bignum_mod.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/bignum_mod_raw.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/camellia.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ccm.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/chacha20.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/chachapoly.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/cipher.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/cipher_wrap.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/cmac.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/constant_time.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ctr_drbg.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/debug.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/des.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/dhm.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ecdh.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ecdsa.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ecjpake.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ecp.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ecp_curves.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/entropy.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/entropy_poll.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/error.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/gcm.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/hkdf.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/hmac_drbg.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/lmots.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/lms.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/mbedtls_platform.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/md5.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/md.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/memory_buffer_alloc.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/mps_reader.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/mps_trace.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/nist_kw.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/oid.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/padlock.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pem.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pk.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pk_ecc.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pkcs12.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pkcs5.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pkcs7.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pkparse.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pk_wrap.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/pkwrite.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/platform.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/platform_util.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/poly1305.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ripemd160.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/rsa_alt_helpers.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/rsa.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/sha1.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/sha256.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/sha512.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_cache.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_ciphersuites.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_client.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_debug_helpers_generated.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_msg.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_ticket.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_tls12_client.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_tls12_server.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_tls13_client.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_tls13_generic.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_tls13_keys.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_tls13_server.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/ssl_tls.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/threading.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/version.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/version_features.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/x509.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/x509_create.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/x509_crl.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/x509_crt.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/x509_csr.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/x509write_crt.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/x509write_csr.c
)

add_library(${LIB_NAME} STATIC ${SRC})

target_include_directories(
  ${LIB_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${MMIOT_ROOT}/framework/src/mbedtls/include
)

set(BUILD_DEFINES MBEDTLS_CONFIG_FILE="morse_mbedtls_config.h")

target_compile_definitions(${LIB_NAME} PUBLIC ${BUILD_DEFINES})
target_compile_options(${LIB_NAME} PRIVATE ${COMPILE_OPTIONS})

target_link_libraries(${LIB_NAME} PRIVATE libmorse)
