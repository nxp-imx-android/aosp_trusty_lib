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

#include <interface/secure_fb/secure_fb.h>
#include <lk/compiler.h>
#include <stdint.h>
#include <trusty_ipc.h>

__BEGIN_CDECLS

/**
 *  DOC: API notes
 *
 *  This header defines an API for implementing hardware-specific secure
 *  framebuffer driver. It is expected that it will be working in conjunction
 *  with a higher level service that will make calls described here.
 */

typedef void* secure_fb_handle_t;

struct secure_fb_impl_buffers {
    size_t num_fbs;
    struct secure_fb_desc fbs[SECURE_FB_MAX_FBS];
    size_t num_handles;
    handle_t handles[SECURE_FB_MAX_FBS];
};

/**
 * secure_fb_impl_init() - This function together with secure_fb_impl_release()
 * frames the life cycle of a secure_fb session. The life cycle begins with this
 * function, and the session is represented by the returned handle.
 *
 * Return: Session handle for the secure_fb session or NULL on failure.
 */
secure_fb_handle_t secure_fb_impl_init(void);

/**
 * secure_fb_impl_get_fbs() - Gets a set of up to %SECURE_FB_MAX_FBS buffers
 * that can be used for rendering. The number of buffers is implementation
 * defined.
 *
 * @session: The active session as returned by a previous call to
 *           secure_fb_imppl_init().
 * @buffers: Describes the buffers returned.
 *
 * Return: SECURE_FB_ERROR_OK on success, or an error code < 0 on failure.
 */
int secure_fb_impl_get_fbs(secure_fb_handle_t session,
                           struct secure_fb_impl_buffers* buffers);

/**
 * secure_fb_impl_display_fb() - Select one of the buffers returned by
 * secure_fb_impl_get_fbs() as active buffer. If only one buffer was
 * returned this function doubles as render complete barrier indicating to the
 * driver that the screen may be updated.
 *
 * @session:   The active session as returned by a previous call to
 *             secure_fb_impl_init().
 * @buffer_id: Indicates one of the buffers returned by
 *             secure_fb_impl_get_fbs(). The @buffer_id is not an index. It
 *             can be found at @buffers.fbs[index].buffer_id with @buffers being
 *             the structure returned by secure_fb_impl_get_fbs().
 *
 * Return: SECURE_FB_ERROR_OK on success, or an error code < 0 on failure.
 */
int secure_fb_impl_display_fb(secure_fb_handle_t session, uint32_t buffer_id);

/**
 * secure_fb_impl_release() - Ends the life cycle of the a secure_fb session.
 * It must relinquish all resources associated with the secure_fb session.
 *
 * @session: The active session as returned by a previous call to
 *           secure_fb_impl_init().
 *
 * Return: SECURE_FB_ERROR_OK on success, or an error code < 0 on failure.
 */
int secure_fb_impl_release(secure_fb_handle_t session);

__END_CDECLS
