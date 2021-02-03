/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define TLOG_TAG "apploader-package"

#include <assert.h>
#include <endian.h>
#include <inttypes.h>
#include <lk/compiler.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "apploader_package.h"

bool apploader_parse_package_metadata(
        struct apploader_package_metadata* metadata,
        struct apploader_package_header* package,
        size_t package_size) {
    size_t package_records_size;
    if (__builtin_sub_overflow(package_size,
                               sizeof(struct apploader_package_header),
                               &package_records_size)) {
        return false;
    }

    for (size_t i = 0; i < APPLOADER_PACKAGE_MAGIC_SIZE; i++) {
        if (READ_ONCE(package->magic[i]) != APPLOADER_PACKAGE_MAGIC[i]) {
            return false;
        }
    }

    uintptr_t records_start;
    if (__builtin_add_overflow((uintptr_t)package,
                               sizeof(struct apploader_package_header),
                               &records_start)) {
        return false;
    }

    uintptr_t records_end;
    if (__builtin_add_overflow(records_start, package_records_size,
                               &records_end)) {
        return false;
    }

    uintptr_t p = records_start;
    while (p < records_end) {
        uint64_t type_length;
        uintptr_t next_p;
        if (__builtin_add_overflow(p, sizeof(type_length), &next_p)) {
            return false;
        }
        if (next_p > records_end) {
            /* The record overflows the package */
            return false;
        }

        memcpy(&type_length, (void*)p, sizeof(type_length));
        p = next_p;
        type_length = be64toh(type_length);

        uint64_t type = type_length >> APPLOADER_RECORD_TYPE_SHIFT;
        uint64_t length = type_length ^ (type << APPLOADER_RECORD_TYPE_SHIFT);

        if (__builtin_add_overflow(p, length, &next_p)) {
            return false;
        }
        if (next_p > records_end) {
            /* The record overflows the package */
            return false;
        }

        switch (type) {
        case APPLOADER_RECORD_TYPE_ELF:
            metadata->elf_start = (uint8_t*)p;
            metadata->elf_size = length;
            break;

        case APPLOADER_RECORD_TYPE_MANIFEST:
            metadata->manifest_start = (uint8_t*)p;
            metadata->manifest_size = length;
            break;

        default:
            /* Ignore unknown types */
            break;
        }

        p = next_p;
    }

    return true;
}
