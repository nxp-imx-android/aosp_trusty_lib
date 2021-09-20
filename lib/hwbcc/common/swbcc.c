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
#include <dice/cbor_writer.h>
#include <dice/dice.h>
#include <dice/ops.h>
#include <dice/ops/trait/cose.h>
#include <dice/utils.h>
#include <interface/hwbcc/hwbcc.h>
#include <lib/hwbcc/common/swbcc.h>
#include <lib/hwkey/hwkey.h>
#include <lib/rng/trusty_rng.h>
#include <stdlib.h>
#include <string.h>
#include <trusty_log.h>
#include <uapi/err.h>

static const uint8_t kdf_ctx[] = "RkpDerivCtx";

static int dice_result_to_err(DiceResult result) {
    switch (result) {
    case kDiceResultOk:
        return NO_ERROR;
    case kDiceResultInvalidInput:
        return ERR_INVALID_ARGS;
    case kDiceResultBufferTooSmall:
        return ERR_NOT_ENOUGH_BUFFER;
    case kDiceResultPlatformError:
        return (int)result;
    }
}

struct swbcc_state {
    uint8_t key_seed[DICE_PRIVATE_KEY_SEED_SIZE];
    uint8_t pub_key[DICE_PUBLIC_KEY_SIZE];
    uint8_t priv_key[DICE_PRIVATE_KEY_SIZE];

    uint8_t test_key_seed[DICE_PRIVATE_KEY_SEED_SIZE];
    uint8_t test_pub_key[DICE_PUBLIC_KEY_SIZE];
    uint8_t test_priv_key[DICE_PRIVATE_KEY_SIZE];

    void* dice_ctx;
};

static int derive_seed(uint8_t* ctx, uint8_t* seed) {
    long rc = hwkey_open();
    if (rc < 0) {
        TLOGE("Failed hwkey_open(): %ld\n", rc);
        return rc;
    }
    hwkey_session_t session = (hwkey_session_t)rc;

    uint32_t kdf_version = HWKEY_KDF_VERSION_1;
    rc = hwkey_derive(session, &kdf_version, ctx, seed,
                      DICE_PRIVATE_KEY_SEED_SIZE);
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
    DiceResult result;
    uint8_t ctx[DICE_PRIVATE_KEY_SEED_SIZE];

    struct swbcc_state* state = (struct swbcc_state*)calloc(1, sizeof(*state));
    if (!state) {
        return ERR_NO_MEMORY;
    }

    STATIC_ASSERT(sizeof(ctx) >= sizeof(*client) + sizeof(kdf_ctx));

    memset(ctx, 0, sizeof(ctx));
    memcpy(ctx, client, sizeof(*client));
    memcpy(ctx + sizeof(*client), kdf_ctx, sizeof(kdf_ctx));

    /* Init BCC keys */
    rc = derive_seed(ctx, state->key_seed);
    if (rc != NO_ERROR) {
        goto err;
    }

    result = DiceKeypairFromSeed(state->dice_ctx, state->key_seed,
                                 state->pub_key, state->priv_key);
    rc = dice_result_to_err(result);
    if (rc != NO_ERROR) {
        TLOGE("Failed to generate keypair: %d\n", rc);
        return rc;
    }

    /* Init test keys */
    rc = trusty_rng_secure_rand(state->test_key_seed,
                                sizeof(state->test_key_seed));
    if (rc != NO_ERROR) {
        goto err;
    }

    result = DiceKeypairFromSeed(state->dice_ctx, state->test_key_seed,
                                 state->test_pub_key, state->test_priv_key);
    rc = dice_result_to_err(result);
    if (rc != NO_ERROR) {
        TLOGE("Failed to generate test keypair: %d\n", rc);
        return rc;
    }

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
#define MAC_SIGN1_SIZE (106)

/*
 * Format and (size) of a Sig_structure in this case is:
 * Array header (1) | Context (11) | Protected Params (4) | AAD Hdr (2) |
 * AAD (var) | MAC KEY Hdr (2) | MAC KEY (32)
 */
#define PROTECTED_PARAMS_BUF_SIZE (4)
#define SIG_STRUCTURE_BUF_SIZE                                         \
    (1 + 11 + PROTECTED_PARAMS_BUF_SIZE + 2 + HWBCC_MAX_AAD_SIZE + 2 + \
     HWBCC_MAC_KEY_SIZE)

int swbcc_sign_mac(swbcc_session_t s,
                   uint32_t test_mode,
                   int32_t cose_algorithm,
                   const uint8_t* mac_key,
                   const uint8_t* aad,
                   size_t aad_size,
                   uint8_t* cose_sign1,
                   size_t cose_sign1_buf_size,
                   size_t* cose_sign1_size) {
    int rc;
    DiceResult result;
    const uint8_t* signing_key;
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

    result = DiceCoseSignAndEncodeSign1(
            state->dice_ctx, mac_key, HWBCC_MAC_KEY_SIZE, aad, aad_size,
            signing_key, cose_sign1_buf_size, cose_sign1, cose_sign1_size);
    rc = dice_result_to_err(result);
    if (rc != NO_ERROR) {
        TLOGE("Failed to generate COSE_Sign1: %d\n", rc);
        return rc;
    }

    return NO_ERROR;
}

/*
 * Format and (size) of a COSE_Sign1 Msg in this case is:
 * Array header (1) | Protected Params (4) | Unprotected Params (1) |
 * CWT Hdr (2) | CWT (76) | Sig Hdr (2) | Sig (64)
 */
#define BCC_SIGN1_SIZE (150)

/*
 * Format and (size) of a Sig_structure in this case is:
 * Array header (1) | Context (11) | Protected Params (4) | AAD (1) |
 * CWT Hdr (2) | CWT (76)
 */
#define BCC_SIG_STRUCTURE_SIZE (95)

/*
 * Format and (size) of BCC in this case is:
 * Array header (1) | Encoded pub key (44) | COSE_Sign1 certificate
 */
#define BCC_TOTAL_SIZE (45 + BCC_SIGN1_SIZE)

static int encode_degenerate_cert(void* dice_ctx,
                                  const uint8_t* seed,
                                  uint8_t* cert,
                                  size_t cert_buf_size,
                                  size_t* cert_size) {
    int rc;
    DiceResult result;
    DiceInputValues input_values;

    /* No need to provide Dice inputs for this self-signed certificate */
    memset(&input_values, 0, sizeof(input_values));

    result = DiceGenerateCertificate(dice_ctx, seed, seed, &input_values,
                                     cert_buf_size, cert, cert_size);
    rc = dice_result_to_err(result);
    if (rc != NO_ERROR) {
        TLOGE("Failed to generate certificate: %d\n", rc);
        return rc;
    }

    return NO_ERROR;
}

int swbcc_get_bcc(swbcc_session_t s,
                  uint32_t test_mode,
                  uint8_t* bcc,
                  size_t bcc_buf_size,
                  size_t* bcc_size) {
    int rc;
    DiceResult result;
    struct CborOut out;
    const uint8_t* seed;
    const uint8_t* pub_key;
    size_t bcc_used;
    struct swbcc_state* state = s;

    assert(s);
    assert(bcc);
    assert(bcc_size);
    assert(bcc_buf_size >= BCC_TOTAL_SIZE);

    if (test_mode) {
        seed = state->test_key_seed;
        pub_key = state->test_pub_key;
    } else {
        seed = state->key_seed;
        pub_key = state->pub_key;
    }

    /* Encode BCC */
    CborOutInit(bcc, bcc_buf_size, &out);
    CborWriteArray(2, &out);
    assert(!CborOutOverflowed(&out));

    bcc_used = CborOutSize(&out);
    bcc += bcc_used;
    bcc_buf_size -= bcc_used;
    *bcc_size = bcc_used;

    /* Encode first entry in the array which is a COSE_Key */
    result = DiceCoseEncodePublicKey(state->dice_ctx, pub_key, bcc_buf_size,
                                     bcc, &bcc_used);
    rc = dice_result_to_err(result);
    if (rc != NO_ERROR) {
        TLOGE("Failed to encode public key: %d\n", rc);
        return rc;
    }

    bcc += bcc_used;
    bcc_buf_size -= bcc_used;
    *bcc_size += bcc_used;

    /* Encode second entry in the array which is a COSE_Sign1 */
    rc = encode_degenerate_cert(state->dice_ctx, seed, bcc, bcc_buf_size,
                                &bcc_used);
    if (rc != NO_ERROR) {
        TLOGE("Failed to generate certificate: %d\n", rc);
        return rc;
    }

    *bcc_size += bcc_used;
    return NO_ERROR;
}
