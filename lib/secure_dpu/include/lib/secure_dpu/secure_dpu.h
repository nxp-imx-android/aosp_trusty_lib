/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <lk/compiler.h>
#include <trusty_ipc.h>

__BEGIN_CDECLS

/**
 * add_secure_dpu_service() - Add secure_dpu service.
 * @hset: pointer to the tipc hset.
 * @chan: the pointer to the handle provided by the caller
 *        for calling secure_dpu_* APIs. The handle will be updated
 *        when the port is connected / disconnected.
 *
 * After the service is added successfully, the service will be started to
 * handle requests.
 *
 * Return: 0 on success, or an error code < 0 on failure.
 */
int add_secure_dpu_service(struct tipc_hset* hset, handle_t* chan);

/**
 * secure_dpu_allocate_buffer() - Allocate framebuffer.
 * @chan: channel handle
 * @buffer_ptr: The physical address of the allocated buffer
 * @buffer_len: The requested size / The size of the allocated buffer
 *
 * Return: 0 on success, or an error code < 0 on failure.
 */
int secure_dpu_allocate_buffer(handle_t chan, void** buffer_ptr, size_t* buffer_len);

/**
 * secure_dpu_free_buffer() - free framebuffer.
 * @chan: channel handle
 * @buffer_ptr: pointer to buffer to be freed
 *
 * Return: 0 on success, or an error code < 0 on failure.
 */
int secure_dpu_free_buffer(handle_t chan, void* buffer_ptr);

/**
 * secure_dpu_start_secure_display() - notify DPU driver to start secure display
 * @chan: channel handle
 *
 * Return: 0 on success, or an error code < 0 on failure.
 */
int secure_dpu_start_secure_display(handle_t chan);

/**
 * secure_dpu_start_secure_display() - notify DPU driver to stop secure display
 * @chan: channel handle
 *
 * Return: 0 on success, or an error code < 0 on failure.
 */
int secure_dpu_stop_secure_display(handle_t chan);

__END_CDECLS
