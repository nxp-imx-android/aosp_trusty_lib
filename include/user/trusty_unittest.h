/*
 * Copyright (C) 2014-2015 The Android Open Source Project
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

// TODO: move this file to a better location
#pragma once

#include <lk/compiler.h>
#include <stdbool.h>
#include <stdio.h>
#include <trusty_log.h>

#define trusty_unittest_printf(args...) \
    do {                                \
        fprintf(stderr, args);          \
        unittest_printf(args);          \
    } while (0)

#include <lk/trusty_unittest.h>

#define PORT_TEST(suite_name, port_name_string)           \
    __BEGIN_CDECLS                                        \
    static bool run_##suite_name(struct unittest* test) { \
        return RUN_ALL_TESTS();                           \
    }                                                     \
                                                          \
    int main(void) {                                      \
        static struct unittest test = {                   \
                .port_name = port_name_string,            \
                .run_test = run_##suite_name,             \
        };                                                \
        struct unittest* tests = &test;                   \
        return unittest_main(&tests, 1);                  \
    }                                                     \
    __END_CDECLS
