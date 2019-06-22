/*
 * Copyright (C) 2015 The Android Open Source Project
 * Copyright NXP 2018
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>

#define HWCRYPTO_PORT "com.android.trusty.hwcrypto"

/**
 * enum hwcrypto_cmd - command identifiers for hwcrypto functions
 */
enum hwcrypto_cmd {
    HWCRYPTO_RESP_BIT = 1,
    HWCRYPTO_REQ_SHIFT = 1,

    HWCRYPTO_HASH = (1 << HWCRYPTO_REQ_SHIFT),
    HWCRYPTO_ENCAP_BLOB = (2 << HWCRYPTO_REQ_SHIFT),
    HWCRYPTO_GEN_RNG    = (3 << HWCRYPTO_REQ_SHIFT),
    HWCRYPTO_GEN_BKEK    = (4 << HWCRYPTO_REQ_SHIFT),
};

/**
 * enum hwcrypto_err - error codes for hwcrypto protocol
 * @HWCRYPTO_ERROR_NONE:             all OK
 * @HWCRYPTO_ERROR_INVALID:          Invalid input
 * @HWCRYPTO_ERROR_INTERNAL:         Error occurred during an operation in Trusty
 */
enum hwcrypto_err {
    HWCRYPTO_ERROR_NONE     = 0,
    HWCRYPTO_ERROR_INVALID  = 1,
    HWCRYPTO_ERROR_INTERNAL = 2,
};

struct hwcrypto_msg {
    uint32_t cmd;
    uint32_t status;
    uint8_t payload[0];
};
