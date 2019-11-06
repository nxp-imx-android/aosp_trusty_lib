/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stddef.h>
#include <stdio.h>
#include <trusty_app_manifest.h>

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest = {
        /* UUID : {3c321776-548e-4978-b676-843cbf1073e5} */
        {0x3c321776,
         0x548e,
         0x4978,
         {0xb6, 0x76, 0x84, 0x3c, 0xbf, 0x10, 0x73, 0xe5}},

        /* optional configuration options here */
        {
                TRUSTY_APP_CONFIG_MIN_STACK_SIZE(1 * 4096),
                TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(1 * 4096),
        },
};
