# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(LIB_NAME mmhostap)
set(SRCS
    ${MMIOT_ROOT}/framework/src/hostap/drivers_morse.c
    ${MMIOT_ROOT}/framework/src/hostap/morse_stubs.c
    ${MMIOT_ROOT}/framework/src/hostap/os_mmosal.c
    ${MMIOT_ROOT}/framework/src/hostap/src/common/dragonfly.c
    ${MMIOT_ROOT}/framework/src/hostap/src/common/hw_features_common.c
    ${MMIOT_ROOT}/framework/src/hostap/src/common/ieee802_11_common.c
    ${MMIOT_ROOT}/framework/src/hostap/src/common/ptksa_cache.c
    ${MMIOT_ROOT}/framework/src/hostap/src/common/sae.c
    ${MMIOT_ROOT}/framework/src/hostap/src/common/wpa_common.c
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto/aes-ctr.c
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto/aes-siv.c
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto/aes-unwrap.c
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto/dh_groups.c
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto/sha256-kdf.c
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto/sha384-kdf.c
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto/tls_none.c
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto/sha512-kdf.c
    ${MMIOT_ROOT}/framework/src/hostap/src/drivers/driver_common.c
    ${MMIOT_ROOT}/framework/src/hostap/src/eap_common/eap_common.c
    ${MMIOT_ROOT}/framework/src/hostap/src/eap_peer/eap.c
    ${MMIOT_ROOT}/framework/src/hostap/src/eap_peer/eap_methods.c
    ${MMIOT_ROOT}/framework/src/hostap/src/eapol_supp/eapol_supp_sm.c
    ${MMIOT_ROOT}/framework/src/hostap/src/rsn_supp/preauth.c
    ${MMIOT_ROOT}/framework/src/hostap/src/rsn_supp/pmksa_cache.c
    ${MMIOT_ROOT}/framework/src/hostap/src/rsn_supp/wpa.c
    ${MMIOT_ROOT}/framework/src/hostap/src/rsn_supp/wpa_ie.c
    ${MMIOT_ROOT}/framework/src/hostap/src/utils/crc32.c
    ${MMIOT_ROOT}/framework/src/hostap/src/utils/bitfield.c
    ${MMIOT_ROOT}/framework/src/hostap/src/utils/common.c
    ${MMIOT_ROOT}/framework/src/hostap/src/utils/wpa_debug.c
    ${MMIOT_ROOT}/framework/src/hostap/src/utils/wpabuf.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/bgscan.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/bgscan_simple.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/autoscan.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/autoscan_exponential.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/bss.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/config.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/eap_register.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/events.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/notify.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/op_classes.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/scan.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/sme.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/wmm_ac.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/wpa_supplicant.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/wpas_glue.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/bssid_ignore.c
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/wnm_sta.c
    ${MMIOT_ROOT}/framework/src/hostap/crypto_mbedtls_mm.c
)

set(INC
    .
    ${MMIOT_ROOT}/framework/src/
    ${MMIOT_ROOT}/framework/src/hostap/
    ${MMIOT_ROOT}/framework/src/hostap/src
    ${MMIOT_ROOT}/framework/src/hostap/src/common
    ${MMIOT_ROOT}/framework/src/hostap/src/utils
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant
    ${MMIOT_ROOT}/framework/src/hostap/src/crypto
)

set(BUILD_DEFINES
    IEEE8021X_EAPOL=1
    CONFIG_SME=1
    CONFIG_SAE=1
    CONFIG_OWE=1
    CONFIG_ECC=1
    CONFIG_SHA256=1
    CONFIG_SHA512=1
    CONFIG_SHA384=1
    CONFIG_FIPS=1
    CONFIG_NO_ACCOUNTING=1
    CONFIG_NO_BSS_TRANS_MGMT=1
    CONFIG_NO_CONFIG_BLOBS=1
    CONFIG_NO_RADIUS=1
    CONFIG_NO_RANDOM_POOL=1
    CONFIG_NO_RC4=1
    CONFIG_NO_ROBUST_AV=1
    CONFIG_NO_RRM=1
    CONFIG_NO_VLAN=1
    CONFIG_WNM=1
    CONFIG_IEEE80211AH=1
    CONFIG_DRIVER_NL80211_MORSE=1
    CONFIG_NO_CONFIG_WRITE=1
    OS_NO_C_LIB_DEFINES=1
    CONFIG_BGSCAN=1
    CONFIG_BGSCAN_SIMPLE=1
    CONFIG_AUTOSCAN=1
    CONFIG_AUTOSCAN_EXPONENTIAL=1
    CONFIG_S1G_TWT=1
    MAX_NUM_MLD_LINKS=1
    MAX_NUM_MLO_LINKS=1
    WPA_SUPPLICANT_CLEANUP_INTERVAL=120
    MM_IOT
    CONFIG_OPENSSL_INTERNAL_AES_WRAP=1
    MM_IOT_DPP_HEADER=1
)

if (CONFIG_WIFI_MORSEMICRO_AP_MODE)
  list(
    APPEND
    SRCS
    ${MMIOT_ROOT}/framework/src/hostap/wpa_supplicant/ap.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/authsrv.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/bss_load.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/wmm.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ap_list.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/comeback_token.c
    ${MMIOT_ROOT}/framework/src/hostap/src/pasn/pasn_responder.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/hw_features.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/dfs.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/tkip_countermeasures.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/hostapd.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ieee802_1x.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ieee802_11_auth.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ieee802_11_s1g.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/sta_info.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ap_config.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ap_drv_ops.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ap_mlme.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/beacon.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/drv_callbacks.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/eap_user_db.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ieee802_11.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ieee802_11_ht.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/ieee802_11_shared.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/neighbor_db.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/pmksa_cache_auth.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/rrm.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/utils.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/wpa_auth.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/wpa_auth_glue.c
    ${MMIOT_ROOT}/framework/src/hostap/src/ap/wpa_auth_ie.c
    ${MMIOT_ROOT}/framework/src/hostap/src/eapol_auth/eapol_auth_sm.c
    ${MMIOT_ROOT}/framework/src/hostap/src/eap_server/eap_server.c
    ${MMIOT_ROOT}/framework/src/hostap/src/eap_server/eap_server_methods.c
  )

  list(APPEND BUILD_DEFINES CONFIG_AP=1 NEED_AP_MLME=1)

  list(APPEND COMPILE_OPTIONS -include ${CMAKE_CURRENT_SOURCE_DIR}/bsd_types_compat.h)
endif ()

add_library(${LIB_NAME} STATIC ${SRCS})
target_include_directories(${LIB_NAME} PUBLIC ${INC})

target_compile_definitions(${LIB_NAME} PUBLIC ${BUILD_DEFINES})
target_compile_options(${LIB_NAME} PRIVATE ${COMPILE_OPTIONS})
target_compile_options(${LIB_NAME} PRIVATE -w)

add_dependencies(${LIB_NAME} mmmbedtls)
target_link_libraries(${LIB_NAME} PRIVATE mmmbedtls mmutils libmorse_interface)
