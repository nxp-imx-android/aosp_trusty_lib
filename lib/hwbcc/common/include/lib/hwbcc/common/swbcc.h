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

#include <lk/compiler.h>
#include <stddef.h>
#include <stdint.h>
#include <uapi/trusty_uuid.h>

__BEGIN_CDECLS

typedef void* swbcc_session_t;

int swbcc_init(swbcc_session_t* s, const struct uuid* client);

void swbcc_close(swbcc_session_t s);

int swbcc_sign_mac(swbcc_session_t s,
                   uint32_t test_mode,
                   int32_t cose_algorithm,
                   const uint8_t* mac_key,
                   const uint8_t* aad,
                   size_t aad_size,
                   uint8_t* cose_sign1,
                   size_t cose_sign1_buf_size,
                   size_t* cose_sign1_size);

int swbcc_get_bcc(swbcc_session_t s,
                  uint32_t test_mode,
                  uint8_t* bcc,
                  size_t bcc_buf_size,
                  size_t* bcc_size);

__END_CDECLS
