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

#include <trusty_app_mgmt.h>
#include <trusty_syscalls.h>

int register_app(void* img_uaddr, uint32_t img_size) {
    return (int)_trusty_register_app(img_uaddr, img_size);
}

int unregister_app(uuid_t* app_uuid) {
    return (int)_trusty_unregister_app(app_uuid);
}
