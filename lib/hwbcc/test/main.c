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

#define TLOG_TAG "hwbcc-test"

#include <lib/hwbcc/client/hwbcc.h>
#include <lib/hwbcc/common/swbcc.h>
#include <trusty_unittest.h>
#include <uapi/err.h>

typedef struct {
    swbcc_session_t s;
} swbcc_t;

/* UUID of this test TA: {0e109d31-8bbe-47d6-bb47-e1dd08910e16} */
static const struct uuid self_uuid = {
        0x0e109d31,
        0x8bbe,
        0x47d6,
        {0xbb, 0x47, 0xe1, 0xdd, 0x08, 0x91, 0x0e, 0x16},
};

static const uint8_t test_mac_key[HWBCC_MAC_KEY_SIZE] = {
        0xf4, 0xe2, 0xd2, 0xbb, 0x2d, 0x07, 0x16, 0xb9, 0x66, 0x4b, 0x73,
        0xe8, 0x56, 0xd3, 0x6e, 0xfb, 0x08, 0xb4, 0x01, 0xd8, 0x86, 0x38,
        0xa7, 0x9a, 0x97, 0xb3, 0x98, 0x4f, 0x63, 0xdc, 0xef, 0xed};

static const uint8_t test_aad[] = {0xcf, 0xe1, 0x89, 0x39, 0xb1,
                                   0x72, 0xbf, 0x4f, 0xa8, 0x0f};

TEST_F_SETUP(swbcc) {
    _state->s = 0;
    int rc = swbcc_init(&_state->s, &self_uuid);
    ASSERT_EQ(rc, 0);

test_abort:;
}

TEST_F_TEARDOWN(swbcc) {
    swbcc_close(_state->s);
}

TEST_F(swbcc, mac) {
    int rc;
    uint8_t cose_sign1[HWBCC_MAX_RESP_PAYLOAD_SIZE];
    size_t cose_sign1_size = 0;

    memset(cose_sign1, 0, sizeof(cose_sign1));

    rc = swbcc_sign_mac(_state->s, true, HWBCC_ALGORITHM_ED25519, test_mac_key,
                        test_aad, sizeof(test_aad), cose_sign1,
                        sizeof(cose_sign1), &cose_sign1_size);
    ASSERT_EQ(rc, 0);

    ASSERT_GT(cose_sign1_size, 0);
    /* TODO: Check contents of cose_sign1. */

test_abort:;
}

TEST_F(swbcc, bcc) {
    int rc;
    uint8_t bcc[HWBCC_MAX_RESP_PAYLOAD_SIZE];
    size_t bcc_size = 0;

    memset(bcc, 0, sizeof(bcc));

    rc = swbcc_get_bcc(_state->s, true, bcc, sizeof(bcc), &bcc_size);
    ASSERT_EQ(rc, 0);

    ASSERT_GT(bcc_size, 0);
    /* TODO: Check contents of bcc. */

test_abort:;
}

/* Check that test mode yields different output every time */
TEST(hwbcc, protected_data_test_mode) {
    int rc;
    uint8_t cose_sign1[HWBCC_MAX_RESP_PAYLOAD_SIZE];
    size_t cose_sign1_size;
    uint8_t bcc[HWBCC_MAX_RESP_PAYLOAD_SIZE];
    size_t bcc_size;

    memset(cose_sign1, 0, sizeof(cose_sign1));
    memset(bcc, 0, sizeof(bcc));

    rc = hwbcc_get_protected_data(true, HWBCC_ALGORITHM_ED25519, test_mac_key,
                                  test_aad, sizeof(test_aad), cose_sign1,
                                  sizeof(cose_sign1), &cose_sign1_size, bcc,
                                  sizeof(bcc), &bcc_size);
    ASSERT_EQ(rc, 0);

    ASSERT_GT(cose_sign1_size, 0);
    ASSERT_GT(bcc_size, 0);
    /* TODO: Check contents of cose_sign1 and bcc. */

test_abort:;
}

TEST(hwbcc, protected_data) {
    int rc;
    uint8_t cose_sign1[HWBCC_MAX_RESP_PAYLOAD_SIZE];
    size_t cose_sign1_size;
    uint8_t bcc[HWBCC_MAX_RESP_PAYLOAD_SIZE];
    size_t bcc_size;

    memset(cose_sign1, 0, sizeof(cose_sign1));
    memset(bcc, 0, sizeof(bcc));

    rc = hwbcc_get_protected_data(true, HWBCC_ALGORITHM_ED25519, test_mac_key,
                                  test_aad, sizeof(test_aad), cose_sign1,
                                  sizeof(cose_sign1), &cose_sign1_size, bcc,
                                  sizeof(bcc), &bcc_size);
    ASSERT_EQ(rc, 0);

    ASSERT_GT(cose_sign1_size, 0);
    ASSERT_GT(bcc_size, 0);
    /* TODO: Check contents of cose_sign1 and bcc. */

test_abort:;
}

PORT_TEST(hwbcc, "com.android.trusty.hwbcc.test");
