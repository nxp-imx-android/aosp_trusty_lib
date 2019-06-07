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

#pragma once

#include <stdint.h>
#include <uapi/trusty_uuid.h>

/* Don't use convenience macros here, it will polute the namespace. */
#ifdef __cplusplus
extern "C" {
#endif

/**
 * register_app(): register an application with the application manager
 * @img_uaddr: application to be registered.
 * @img_size: size of the application to be registered.
 *
 * Return: negative error code on error, 0 otherwise
 */
int register_app(void* img_uaddr, uint32_t img_size);

/**
 * unregister_app(): unregister an application from the application manager
 * @app_uuid: pointer to the uuid of the application to be unregistered
 *
 * Only applications that were previously registered with register_app and are
 * not currently running are elegible to be unregistered.
 *
 * Return: negative error code on error, 0 otherwise
 *
 * XXX:UPDATE DOC
 */
int unregister_app(uuid_t* app_uuid);

#ifdef __cplusplus
}
#endif
