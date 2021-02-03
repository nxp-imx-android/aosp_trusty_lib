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

/**
 * enum apploader_package_format_version - Version number for the apploader
 *                                         package format
 * @APPLOADER_PACKAGE_FORMAT_VERSION_CURRENT:
 *      The current version of the apploader package format
 */
enum apploader_package_format_version : uint64_t {
    APPLOADER_PACKAGE_FORMAT_VERSION_CURRENT = 1,
};

/**
 * enum apploader_package_header_label - Key labels for the ```headers```
 *                                       field in apploader packages
 */
enum apploader_package_header_label : uint64_t {};

/**
 * enum apploader_package_cbor_tag - CBOR tags used by the apploader
 * @APPLOADER_PACKAGE_CBOR_TAG_APP:
 *      Tag marking an application package
 */
enum apploader_package_cbor_tag : uint64_t {
    APPLOADER_PACKAGE_CBOR_TAG_APP = 65536,
};
