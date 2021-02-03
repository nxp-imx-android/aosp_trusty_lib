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

#pragma once

/*
 * An apploader package consists of the following:
 *   * The package header, followed by
 *   * 0 or more package records
 *
 *  The package header is a struct apploader_package_header described below,
 *  and currently only contains an 8-byte TrustyAp magic value.
 *
 *  Each package record is encoded using a type-length-value scheme with the
 *  following components:
 *
 *    * The type-length pair encoded together as a big-endian 64-bit value,
 *      split further into:
 *
 *      * The type, stored in the most significant 16 bits of the
 *        type-length pair. Is one of the values in enum apploader_record_type.
 *
 *      * The length, stored in the least significant 48 bits of the pair.
 *        Represents the total size of the subsequent payload (excluding the
 *        type-length pair itself).
 *
 *    * The payload immediately after the type-length pair.
 *
 */

#define APPLOADER_PACKAGE_MAGIC "TrustyAp"
#define APPLOADER_PACKAGE_MAGIC_SIZE 8

/**
 * struct apploader_package_header - the header of a package
 * @magic: magic number used for validation
 *
 * The actual package follows immediately after the header.
 */
struct apploader_package_header {
    uint8_t magic[APPLOADER_PACKAGE_MAGIC_SIZE];
};

#define APPLOADER_RECORD_TYPE_SHIFT 48

enum apploader_record_type : uint64_t {
    APPLOADER_RECORD_TYPE_ELF = 0,
    APPLOADER_RECORD_TYPE_MANIFEST = 1,
};

/**
 * struct apploader_package_metadata - package metadata, parsed from the package
 * @elf_size: size of the embedded ELF image
 * @elf_start: pointer to the start of the ELF image
 * @manifest_size: size of the manifest
 * @manifest_start: pointer to the start of the manifest
 *
 * This structure contains metadata about the package, parsed from the package
 * data by the apploader_parse_package_metadata() function.
 */
struct apploader_package_metadata {
    uint64_t elf_size;
    uint8_t* elf_start;

    uint64_t manifest_size;
    uint8_t* manifest_start;
};

bool apploader_parse_package_metadata(
        struct apploader_package_metadata* metadata,
        struct apploader_package_header* package,
        size_t package_size);
