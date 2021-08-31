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

#define TLOG_TAG "swbcc"

#include <assert.h>
#include <interface/hwbcc/hwbcc.h>
#include <lib/hwbcc/common/swbcc.h>
#include <lib/hwkey/hwkey.h>
#include <lib/rng/trusty_rng.h>
#include <openssl/curve25519.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_log.h>
#include <uapi/err.h>

#define HW_KEY_SIZE 32

static const uint8_t kdf_ctx[] = "RkpDerivCtx";

struct swbcc_state {
    uint8_t pub_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t priv_key[ED25519_PRIVATE_KEY_LEN];
    uint8_t test_pub_key[ED25519_PUBLIC_KEY_LEN];
    uint8_t test_priv_key[ED25519_PRIVATE_KEY_LEN];
};

static int derive_bytes(uint8_t* ctx, uint8_t* bytes) {
    long rc = hwkey_open();
    if (rc < 0) {
        TLOGE("Failed hwkey_open(): %ld\n", rc);
        return rc;
    }
    hwkey_session_t session = (hwkey_session_t)rc;

    uint32_t kdf_version = HWKEY_KDF_VERSION_1;
    rc = hwkey_derive(session, &kdf_version, ctx, bytes, HW_KEY_SIZE);
    if (rc != NO_ERROR) {
        TLOGE("Failed hwkey_derive(): %ld\n", rc);
        goto out;
    }

    rc = NO_ERROR;

out:
    hwkey_close(session);
    return (int)rc;
}

int swbcc_init(swbcc_session_t* s, const struct uuid* client) {
    int rc;
    uint8_t seed[HW_KEY_SIZE];
    uint8_t ctx[HW_KEY_SIZE];

    struct swbcc_state* state = (struct swbcc_state*)calloc(1, sizeof(*state));
    if (!state) {
        return ERR_NO_MEMORY;
    }
    STATIC_ASSERT(sizeof(ctx) >= sizeof(*client) + sizeof(kdf_ctx));

    memset(ctx, 0, sizeof(ctx));
    memcpy(ctx, client, sizeof(*client));
    memcpy(ctx + sizeof(*client), kdf_ctx, sizeof(kdf_ctx));

    rc = derive_bytes(ctx, seed);
    if (rc != NO_ERROR) {
        goto err;
    }

    ED25519_keypair_from_seed(state->pub_key, state->priv_key, seed);

    rc = trusty_rng_secure_rand(seed, sizeof(seed));
    if (rc != NO_ERROR) {
        goto err;
    }

    ED25519_keypair_from_seed(state->test_pub_key, state->test_priv_key, seed);

    *s = (swbcc_session_t)state;
    return NO_ERROR;

err:
    free(state);
    return rc;
}

void swbcc_close(swbcc_session_t s) {
    free(s);
}

/*
 * Format and (size) of a COSE_Sign1 Msg in this case is:
 * Array header (1) | Protected Params (4) | Unprotected Params (1) |
 * MAC Key Hdr (2) | MAC Key (32) | Sig Hdr (2) | Sig (64)
 */
#define MAC_SIGN1_SIZE 106
#define MAC_SIGN1_MAC_KEY_OFFSET 8
#define MAC_SIGN1_SIG_HDR_OFFSET 40
#define MAC_SIGN1_SIG_OFFSET 42

#define FOUR_ENTRY_ARRAY 0x84
#define PROTECTED_PARAMS 0x43, 0xA1, 0x01, 0x27
#define UNPROTECTED_PARAMS 0xA0
#define MAC_KEY_HDR 0x58, 0x20
#define SIGNATURE_HDR 0x58, 0x40

/* Array of length four, with the first "Signature1" entry */
static const uint8_t sig_structure_hdr[] = {0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E,
                                            0x61, 0x74, 0x75, 0x72, 0x65, 0x31};

/* Bstr encoding of the map {1 : -7} */
static const uint8_t protected_params[] = {PROTECTED_PARAMS};

/* Bstr with 32 bytes to follow */
static const uint8_t mac_key_payload_hdr[] = {MAC_KEY_HDR};

/* Bstr with 64 bytes to follow */
static const uint8_t signature_hdr[] = {SIGNATURE_HDR};

static const uint8_t sign1_msg_template[] = {FOUR_ENTRY_ARRAY, PROTECTED_PARAMS,
                                             UNPROTECTED_PARAMS, MAC_KEY_HDR};
/*
 * Format and (size) of a Sig_structure in this case is:
 * Array header (1) | Context (11) | Protected Params (4) | AAD (var) |
 * MAC KEY HDR + MAC KEY (34)
 */
#define SIG_STRUCTURE_BUFFER_SIZE                           \
    (sizeof(sig_structure_hdr) + sizeof(protected_params) + \
     HWBCC_MAX_AAD_SIZE + sizeof(mac_key_payload_hdr) + HWBCC_MAC_KEY_SIZE)

static int sign_mac(const uint8_t* signing_key,
                    const uint8_t* mac_key,
                    const uint8_t* aad,
                    size_t aad_size,
                    uint8_t* cose_sign1,
                    size_t cose_sign1_buf_size,
                    size_t* cose_sign1_size) {
    uint8_t sig_structure[SIG_STRUCTURE_BUFFER_SIZE];
    uint8_t* sig_pointer = sig_structure;
    size_t sig_structure_size = 0;

    memcpy(cose_sign1, sign1_msg_template, sizeof(sign1_msg_template));
    memcpy(cose_sign1 + MAC_SIGN1_MAC_KEY_OFFSET, mac_key, HWBCC_MAC_KEY_SIZE);
    memcpy(cose_sign1 + MAC_SIGN1_SIG_HDR_OFFSET, signature_hdr,
           sizeof(signature_hdr));

    /* Serialize a COSE Sig_structure to be signed. */
    memcpy(sig_pointer, sig_structure_hdr, sizeof(sig_structure_hdr));
    sig_structure_size += sizeof(sig_structure_hdr);

    memcpy(sig_pointer + sig_structure_size, protected_params,
           sizeof(protected_params));
    sig_structure_size += sizeof(protected_params);

    memcpy(sig_pointer + sig_structure_size, aad, aad_size);
    sig_structure_size += aad_size;

    memcpy(sig_pointer + sig_structure_size, mac_key_payload_hdr,
           sizeof(mac_key_payload_hdr));
    sig_structure_size += sizeof(mac_key_payload_hdr);

    memcpy(sig_pointer + sig_structure_size, mac_key, HWBCC_MAC_KEY_SIZE);
    sig_structure_size += HWBCC_MAC_KEY_SIZE;

    if (!ED25519_sign(cose_sign1 + MAC_SIGN1_SIG_OFFSET, sig_structure,
                      sig_structure_size, signing_key)) {
        TLOGE("MAC key signing failed\n");
        return ERR_GENERIC;
    }

    *cose_sign1_size = MAC_SIGN1_SIZE;
    return NO_ERROR;
}

int swbcc_sign_mac(swbcc_session_t s,
                   uint32_t test_mode,
                   int32_t cose_algorithm,
                   const uint8_t* mac_key,
                   const uint8_t* aad,
                   size_t aad_size,
                   uint8_t* cose_sign1,
                   size_t cose_sign1_buf_size,
                   size_t* cose_sign1_size) {
    const uint8_t* signing_key = NULL;
    struct swbcc_state* state = s;

    assert(s);
    assert(mac_key);
    assert(aad);
    assert(cose_sign1);
    assert(cose_sign1_size);
    assert(cose_sign1_buf_size >= MAC_SIGN1_SIZE);

    if (cose_algorithm != HWBCC_ALGORITHM_ED25519) {
        TLOGE("Signing algorithm is not supported: %d\n", cose_algorithm);
        return ERR_NOT_SUPPORTED;
    }

    signing_key = test_mode ? state->test_priv_key : state->priv_key;

    return sign_mac(signing_key, mac_key, aad, aad_size, cose_sign1,
                    cose_sign1_buf_size, cose_sign1_size);
}

#define CBOR_WEB_TOKEN_HDR 0x58, 0x4C
#define FOUR_ENTRY_MAP 0xA4
#define ISSUER_ENTRY 0x01, 0x66, 0x49, 0x73, 0x73, 0x75, 0x65, 0x72
#define SUBJECT_ENTRY 0x02, 0x67, 0x53, 0x75, 0x62, 0x6A, 0x65, 0x63, 0x74
#define PUBLIC_KEY_ENTRY 0x3A, 0x00, 0x47, 0x44, 0x57, 0x58, 0x2C
#define PUBLIC_KEY_DEF \
    0xA5, 0x01, 0x01, 0x03, 0x27, 0x04, 0x02, 0x20, 0x06, 0x21, 0x58, 0x20
#define ZEROED_PUB_KEY                                                         \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
            0, 0, 0, 0, 0, 0, 0
#define KEY_USAGE_ENTRY 0x3A, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20

#define EMPTY_BSTR 0x40

#define TWO_ENTRY_ARRAY 0x82
#define PROTECTED_DATA_PAYLOAD_HDR_SIZE (1)
#define ENCODED_PUB_KEY_SIZE (44)

/*
 * Format and (size) of a COSE_Sign1 Msg in this case is:
 * Array header (1) | Protected Params (4) | Unprotected Params (1) |
 * CWT Hdr (2) | CWT (76) | Sig Hdr (2) | Sig (64)
 */
#define BCC_SIGN1_SIZE 150
#define BCC_SIGN1_ENCODED_CWT_SIZE 78
#define BCC_SIGN1_CWT_HDR_OFFSET 6
#define BCC_SIGN1_CWT_PUB_KEY_OFFSET 45
#define BCC_SIGN1_SIG_HDR_OFFSET 84
#define BCC_SIGN1_SIG_OFFSET 86

static const uint8_t bcc_sign1_template[] = {
        FOUR_ENTRY_ARRAY,   PROTECTED_PARAMS, UNPROTECTED_PARAMS,
        CBOR_WEB_TOKEN_HDR, FOUR_ENTRY_MAP,   ISSUER_ENTRY,
        SUBJECT_ENTRY,      PUBLIC_KEY_ENTRY, PUBLIC_KEY_DEF,
        ZEROED_PUB_KEY,     KEY_USAGE_ENTRY,  SIGNATURE_HDR};

static const uint8_t pub_key_entry[] = {PUBLIC_KEY_DEF};

/*
 * Format and (size) of a Sig_structure in this case is:
 * Array header (1) | Context (11) | Protected Params (4) | AAD (1) |
 * CWT HDR + CWT (78)
 */
#define BCC_SIG_STRUCTURE_SIZE 95

#define BCC_TOTAL_SIZE \
    BCC_SIGN1_SIZE + PROTECTED_DATA_PAYLOAD_HDR_SIZE + ENCODED_PUB_KEY_SIZE

static int get_bcc(const uint8_t* signing_key,
                   uint8_t* bcc,
                   size_t bcc_buf_size,
                   size_t* bcc_size) {
    uint8_t sig_structure[BCC_SIG_STRUCTURE_SIZE];
    uint8_t* sig_pointer = sig_structure;
    size_t sig_structure_size = 0;
    uint8_t* bcc_ptr = bcc;

    bcc_ptr[0] = TWO_ENTRY_ARRAY;
    bcc_ptr++;
    memcpy(bcc_ptr, pub_key_entry, sizeof(pub_key_entry));
    bcc_ptr += sizeof(pub_key_entry);
    memcpy(bcc_ptr, signing_key + ED25519_PUBLIC_KEY_LEN,
           ED25519_PUBLIC_KEY_LEN);
    bcc_ptr += ED25519_PUBLIC_KEY_LEN;

    memcpy(bcc_ptr, bcc_sign1_template, sizeof(bcc_sign1_template));
    /*
     * Boringssl formats an Ed25519 private key as (priv key | pub key) for a
     * total of 64 bytes.
     */
    memcpy(bcc_ptr + BCC_SIGN1_CWT_PUB_KEY_OFFSET,
           signing_key + ED25519_PUBLIC_KEY_LEN, ED25519_PUBLIC_KEY_LEN);

    memcpy(sig_pointer, sig_structure_hdr, sizeof(sig_structure_hdr));
    sig_structure_size += sizeof(sig_structure_hdr);

    memcpy(sig_pointer + sig_structure_size, protected_params,
           sizeof(protected_params));
    sig_structure_size += sizeof(protected_params);

    sig_pointer[sig_structure_size] = EMPTY_BSTR;
    sig_structure_size++;

    memcpy(sig_pointer + sig_structure_size, bcc_ptr + BCC_SIGN1_CWT_HDR_OFFSET,
           BCC_SIGN1_ENCODED_CWT_SIZE);
    sig_structure_size += BCC_SIGN1_ENCODED_CWT_SIZE;

    if (!ED25519_sign(bcc_ptr + BCC_SIGN1_SIG_OFFSET, sig_structure,
                      sig_structure_size, signing_key)) {
        TLOGE("MAC key signing failed");
        return ERR_GENERIC;
    }
    *bcc_size = BCC_TOTAL_SIZE;
    return NO_ERROR;
}

int swbcc_get_bcc(swbcc_session_t s,
                  uint32_t test_mode,
                  uint8_t* bcc,
                  size_t bcc_buf_size,
                  size_t* bcc_size) {
    const uint8_t* signing_key = NULL;
    struct swbcc_state* state = s;

    assert(s);
    assert(bcc);
    assert(bcc_size);
    assert(bcc_buf_size >= BCC_TOTAL_SIZE);

    signing_key = test_mode ? state->test_priv_key : state->priv_key;

    return get_bcc(signing_key, bcc, bcc_buf_size, bcc_size);
}
