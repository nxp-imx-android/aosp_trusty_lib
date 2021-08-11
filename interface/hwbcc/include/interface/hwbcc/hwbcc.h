/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

// Boringssl suffixes the private key with the public key
#define BSSL_ED25519_PRIV_KEY_LENGTH 64

#define HWBCC_PORT "com.android.trusty.hwbcc"

/**
 * enum hwbcc_cmd - BCC service commands
 *
 * @HWBCC_CMD_REQ_SHIFT: bitshift of the command index
 * @HWBCC_CMD_RSP_BIT: bit indicating that this is a response
 * @HWBCC_CMD_SIGN_MAC: sign the provided MAC key
 */
enum hwbcc_cmd {
    HWBCC_CMD_REQ_SHIFT = 1,
    HWBCC_CMD_RSP_BIT = 1,
    HWBCC_CMD_SIGN_MAC = 0 << HWBCC_CMD_REQ_SHIFT,
    HWBCC_CMD_GET_BCC = 1 << HWBCC_CMD_REQ_SHIFT
};

/**
 * enum hwbcc_err - error codes for HWBCC protocol
 * @HWBCC_STATUS_SUCCESS:        command success.
 * @HWBCC_STATUS_INTERNAL_ERROR: unknown error.
 * @HWBCC_STATUS_INVALID_ARGS:   input not valid. E.g. MAC key isn't the correct
 * size.
 * @HWBCC_STATUS_SIGNING_FAILED: signature over the data provided in the request
 * failed.
 */
enum hwbcc_status {
    HWBCC_STATUS_SUCCESS = 0,
    HWBCC_STATUS_INTERNAL_ERROR = 1,
    HWBCC_STATUS_INVALID_ARGS = 2,
    HWBCC_STATUS_SIGNING_FAILED = 3,
    HWBCC_STATUS_INVALID_REQUEST = 4,
};

#define RKP_MAC_KEY_LENGTH 32

/**
 * struct hwbcc_req_hdr - Generic header for all hwbcc requests.
 *
 * @cmd:       The command to be run. Commands are described in hwbcc_cmd.
 * @test_mode: Whether or not RKP is making a test request.
 */
struct hwbcc_req_hdr {
    uint32_t cmd;
    uint8_t test_mode;
};

/**
 * struct hwbcc_req_sign_mac_hdr - Request info to sign a MAC key.
 *
 * @total_length:               Total length of the payload to follow this
 *                              header. This is the sum of all other length
 *                              fields in this header.
 * @protected_headers_length:   Length of the P_HDR
 * @unprotected_headers_length: Length of the U_HDR
 * @external_aad_length:        Length of the AAD
 * @signing_key_length          Length of the key to use for signing.
 * @mac_length:                 Length of the MAC key
 * This request should be followed by data formatted in the following style:
 *     (P_HDR | U_HDR | AAD | SK | MK)
 * P_HDR - CBOR bstr representing protected hdrs
 * U_HDR - CBOR map representing unprotected hdrs
 * AAD   - external AAD to be included in the sig
 * SK    - The signing key used to sign the MK
 * MK    - the 32-byte MAC key to sign
 */
struct hwbcc_req_sign_mac_hdr {
    uint32_t total_length;
    uint32_t protected_headers_length;
    uint32_t unprotected_headers_length;
    uint32_t external_aad_length;
    uint32_t signing_key_length;
    uint32_t mac_length;
};

#define MAX_REQUEST_SIZE 500
struct full_hwbcc_req_sign_mac {
    struct hwbcc_req_sign_mac_hdr sign_mac;
    uint8_t payload[MAX_REQUEST_SIZE];
};

/**
 * struct hwbcc_req_get_bcc - Request info to fetch a boot certificate chain
 *                            and the corresponding key.
 * @device_priv_key: The Ed25519 key to use for signing.
 *
 */
struct hwbcc_req_get_bcc {
    uint8_t device_priv_key[BSSL_ED25519_PRIV_KEY_LENGTH];
};

/**
 * @cmd:           The command that was interpreted by the server.
 * @status:        Whether or not the cmd succeeded, or how it failed. Values
 *                 are specified by hwbcc_err.
 * @response_size: The length of the resulting payload to be returned.
 */
struct hwbcc_resp_hdr {
    uint32_t cmd;
    uint32_t status;
    uint64_t response_size;
};
