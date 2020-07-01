/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <stdio.h>

#ifdef USER_TASK_WITH_TRUSTY_USER_BASE_LIB_UNITTEST
#include <lib/unittest/unittest.h>
#else
static inline int unittest_printf(const char* fmt, ...) {
    return 0;
}
#endif

#define TLOG_LVL_NONE 0
#define TLOG_LVL_CRIT 1
#define TLOG_LVL_ERROR 2
#define TLOG_LVL_WARN 3
#define TLOG_LVL_INFO 4
#define TLOG_LVL_DEBUG 5

#ifndef TLOG_LVL
#define TLOG_LVL TLOG_LVL_INFO
#endif

#define TLOG(fmt, ...)                                                      \
    do {                                                                    \
        fprintf(stderr, "%s: %d: " fmt, TLOG_TAG, __LINE__, ##__VA_ARGS__); \
        unittest_printf("%s: %d: " fmt, TLOG_TAG, __LINE__, ##__VA_ARGS__); \
    } while (0)

/* debug  */
#define TLOGD(x...)                       \
    do {                                  \
        if (TLOG_LVL >= TLOG_LVL_DEBUG) { \
            TLOG(x);                      \
        }                                 \
    } while (0)

/* info */
#define TLOGI(x...)                      \
    do {                                 \
        if (TLOG_LVL >= TLOG_LVL_INFO) { \
            fprintf(stderr, "%s: " x, TLOG_TAG); \
            unittest_printf("%s: " x, TLOG_TAG); \
        }                                \
    } while (0)

/* warning */
#define TLOGW(x...)                      \
    do {                                 \
        if (TLOG_LVL >= TLOG_LVL_WARN) { \
            TLOG(x);                     \
        }                                \
    } while (0)

/* error */
#define TLOGE(x...)                       \
    do {                                  \
        if (TLOG_LVL >= TLOG_LVL_ERROR) { \
            TLOG(x);                      \
        }                                 \
    } while (0)

/* critical */
#define TLOGC(x...)                      \
    do {                                 \
        if (TLOG_LVL >= TLOG_LVL_CRIT) { \
            TLOG(x);                     \
        }                                \
    } while (0)
