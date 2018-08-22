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

#include <lk/compiler.h>
#include <stdbool.h>
#include <trusty_ipc.h>

__BEGIN_CDECLS

struct unittest {
    const char* port_name;
    bool (*run_test)(struct unittest* test);
    handle_t _port_handle;
};

int unittest_printf(const char* fmt, ...);
int unittest_main(struct unittest** tests, size_t test_count);

__END_CDECLS
